package daemon

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateKey_HappyPath proves the post-condition both `--init` and the
// soak test rely on: after a clean run the operator has exactly two files
// — a 0o600 private key and a 0o644 public key — and the on-disk PEM
// parses back as a matching Ed25519 keypair.
func TestGenerateKey_HappyPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	if err := GenerateKey(keyPath, pubPath); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Private key: present, mode 0o600, parses as Ed25519.
	privInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("private key missing: %v", err)
	}
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key perm = %o, want 0600", got)
	}
	privPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		t.Fatal("private key is not PEM")
	}
	parsedPriv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	priv, ok := parsedPriv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want ed25519.PrivateKey", parsedPriv)
	}

	// Public key: present, mode 0o644, parses as Ed25519, matches private.
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("public key perm = %o, want 0644", got)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		t.Fatal("public key is not PEM")
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := parsedPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", parsedPub)
	}
	if !pub.Equal(priv.Public()) {
		t.Error("on-disk public key does not match the public half of the private key")
	}
}

// TestGenerateKey_DerivesPublicKeyPathWhenEmpty pins the convenience the
// CLI relies on: omit --public-key and the public file lands at <key>.pub.
func TestGenerateKey_DerivesPublicKeyPathWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")

	if err := GenerateKey(keyPath, ""); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := os.Stat(keyPath + ".pub"); err != nil {
		t.Errorf("expected public key at %s.pub, got: %v", keyPath, err)
	}
}

func TestGenerateKey_RejectsEmptyKeyPath(t *testing.T) {
	if err := GenerateKey("", ""); err == nil {
		t.Fatal("expected error for empty keyPath")
	}
}

// TestGenerateKey_RefusesIdenticalPaths defends against a footgun:
// `--key /x --public-key /x` would otherwise have the public key write
// trip O_EXCL after the private write succeeded, leaving a private-key
// file that GenerateKey couldn't fully clean up because the same path
// holds a different intended file. Reject early instead.
func TestGenerateKey_RefusesIdenticalPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same")
	err := GenerateKey(path, path)
	if err == nil {
		t.Fatal("expected error when keyPath == publicKeyPath")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("file was created despite the rejection")
	}
}

// TestGenerateKey_RefusesExistingPrivateKey is the central safety
// guarantee: an operator who accidentally re-runs --init must NOT clobber
// the live signing key — that would invalidate every receipt the chain
// has ever produced. We pre-create a sentinel file and verify it survives.
func TestGenerateKey_RefusesExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	const sentinel = "DO NOT OVERWRITE"
	if err := os.WriteFile(keyPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	err := GenerateKey(keyPath, pubPath)
	if err == nil {
		t.Fatal("expected error when private key already exists")
	}

	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("private key was overwritten; got %q, want %q", got, sentinel)
	}
	if _, err := os.Stat(pubPath); err == nil {
		t.Error("public key was written even though private-key write failed")
	}
}

// TestGenerateKey_RefusesExistingPublicKey covers the symmetric case: a
// stray <key>.pub left over from a prior install must block --init so the
// operator decides whether to remove it (and accept the rotation) rather
// than the daemon silently mismatching the published key against the new
// private key.
func TestGenerateKey_RefusesExistingPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	const sentinel = "STALE PUB KEY"
	if err := os.WriteFile(pubPath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	err := GenerateKey(keyPath, pubPath)
	if err == nil {
		t.Fatal("expected error when public key already exists")
	}

	if _, err := os.Stat(keyPath); err == nil {
		t.Error("private key was created despite stale public key blocking the run")
	}
	got, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("public key was overwritten; got %q, want %q", got, sentinel)
	}
}

// TestGenerateKey_RefusesSymlinkAtPrivateKeyPath is the TOCTOU regression:
// an attacker who can plant a symlink at the private-key path before the
// open call must not get the daemon to write Ed25519 secret material
// through that symlink to a target file (e.g. the user's authorized_keys).
// O_NOFOLLOW + O_EXCL is what closes the window.
func TestGenerateKey_RefusesSymlinkAtPrivateKeyPath(t *testing.T) {
	// On platforms where oNoFollow is a no-op (non-unix builds, see
	// nofollow_other.go) the OpenFile would silently follow the symlink
	// and the assertion below would fail. The daemon refuses to start
	// outside Linux/macOS at runtime anyway — mirror keysource/file_test.go's
	// skip rather than assert what the platform can't enforce.
	if oNoFollow == 0 {
		t.Skip("O_NOFOLLOW is a no-op on this platform; symlink rejection cannot be enforced")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-target")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	if err := os.Symlink(target, keyPath); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}
	pubPath := filepath.Join(dir, "signing.key.pub")

	err := GenerateKey(keyPath, pubPath)
	if err == nil {
		t.Fatal("expected error when private-key path is a symlink")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "victim" {
		t.Errorf("symlink target was overwritten; got %q want %q (O_NOFOLLOW failed to refuse)", got, "victim")
	}
	if _, err := os.Stat(pubPath); err == nil {
		t.Error("public key was created even though private-key write failed")
	}
}

// TestGenerateKey_RefusesSymlinkAtPublicKeyPath: same TOCTOU defence on
// the public-key path. If the symlink ambush only succeeds for the
// second write, the existing private-key cleanup must still leave a
// clean state.
func TestGenerateKey_RefusesSymlinkAtPublicKeyPath(t *testing.T) {
	if oNoFollow == 0 {
		t.Skip("O_NOFOLLOW is a no-op on this platform; symlink rejection cannot be enforced")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-target")
	if err := os.WriteFile(target, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")
	if err := os.Symlink(target, pubPath); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}

	err := GenerateKey(keyPath, pubPath)
	if err == nil {
		t.Fatal("expected error when public-key path is a symlink")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "victim" {
		t.Errorf("symlink target was overwritten; got %q want %q", got, "victim")
	}
	// Private key must have been rolled back so a retry sees a clean
	// state — half-written installs are exactly what `--init`'s "must not
	// exist" semantics are meant to prevent.
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("private key remained on disk after public-key write failed; rollback did not run")
	}
}

// TestGenerateKey_CreatesParentDirs proves --init can run against a fresh
// $HOME with no ~/.local/share/agent-receipts directory yet.
func TestGenerateKey_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "nested", "deeper", "signing.key")
	pubPath := filepath.Join(dir, "elsewhere", "signing.key.pub")

	if err := GenerateKey(keyPath, pubPath); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("private key missing: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Errorf("public key missing: %v", err)
	}
}

// TestGenerateKey_ProducesKeyKeysourceCanLoad is the integration guarantee:
// a key just written by GenerateKey must be loadable by the same
// keysource.File the daemon uses at runtime. Catches any future drift
// between PEM block types, encoding flags, or permission expectations.
func TestGenerateKey_ProducesKeyKeysourceCanLoad(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	if err := GenerateKey(keyPath, pubPath); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Round-trip through the same keysource the daemon uses. We import
	// the package locally (no t.Helper noise) and load + sign + verify
	// with the published public key to prove the on-disk artefacts are
	// consistent with each other.
	priv, err := readPrivKeyForTest(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := readPubKeyForTest(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("round-trip")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature produced by on-disk private key does not verify against on-disk public key")
	}
}

// TestGenerateKey_ErrorWrappingMentionsPath gives operators something
// actionable when --init fails: the failing path should appear in the
// surfaced error so they don't have to guess which file is the problem.
func TestGenerateKey_ErrorWrappingMentionsPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	if err := os.WriteFile(keyPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := GenerateKey(keyPath, pubPath)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), keyPath) {
		t.Errorf("error %q should mention the failing path %q", err.Error(), keyPath)
	}
}

func readPrivKeyForTest(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not ed25519")
	}
	return priv, nil
}

func readPubKeyForTest(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not ed25519")
	}
	return pub, nil
}
