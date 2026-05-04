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

	"github.com/agent-receipts/ar/daemon/internal/keysource"
)

func TestTightenDBFiles_TightensFresh0644(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatalf("tightenDBFiles should chmod 0644 -> 0640, not refuse: %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("perm = %o, want 0640", got)
	}
}

func TestTightenDBFiles_TightensTo0640(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("perm = %o, want 0640", got)
	}
}

func TestTightenDBFiles_PreservesTighter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 0600 must NOT be widened to 0640.
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("perm = %o, want 0600 (operator's tighter choice must be preserved)", got)
	}
}

// TestTightenDBFiles_Tightens0604 is the regression test for the bitmask bug:
// 0604 (rw----r--) is world-readable but numerically less than 0640, so a
// `Perm() > 0640` comparison would let it through unchanged. The bitmask
// check must catch it.
func TestTightenDBFiles_Tightens0604(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatalf("tightenDBFiles should chmod 0604 -> 0640, not refuse: %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o007 != 0 {
		t.Errorf("after tighten, perm = %o, world bits should be cleared", got)
	}
	if got := info.Mode().Perm(); looserThanAllowed(got) {
		t.Errorf("after tighten, perm = %o is still looser than %o", got, allowedDBPerm)
	}
}

func TestTightenDBFiles_NoErrorWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := tightenDBFiles(filepath.Join(dir, "does-not-exist.db")); err != nil {
		t.Errorf("absent DB should be a no-op, got: %v", err)
	}
}

// stubKeySource lets publishPublicKey tests inject deterministic / malformed
// public keys without spinning up a real keysource.File from disk.
type stubKeySource struct {
	pub    string
	pubErr error
}

func (s *stubKeySource) Init() error                      { return nil }
func (s *stubKeySource) Sign(_ []byte) ([]byte, error)    { return nil, nil }
func (s *stubKeySource) PublicKey() (string, error)       { return s.pub, s.pubErr }
func (s *stubKeySource) VerificationMethod() string       { return "did:test#k1" }
func (s *stubKeySource) Rotate() error                    { return keysource.ErrNotImplemented }
func (s *stubKeySource) Teardown() error                  { return nil }

func TestPublishPublicKey_WritesFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pub")
	ks := &stubKeySource{pub: "-----BEGIN PUBLIC KEY-----\nABCD\n-----END PUBLIC KEY-----\n"}

	if err := publishPublicKey(ks, path); err != nil {
		t.Fatalf("publishPublicKey: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ks.pub {
		t.Errorf("contents = %q, want %q", got, ks.pub)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("perm = %o, want 0644", perm)
	}
}

func TestPublishPublicKey_NoOpOnIdenticalContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pub")
	pub := "-----BEGIN PUBLIC KEY-----\nABCD\n-----END PUBLIC KEY-----\n"
	if err := os.WriteFile(path, []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := publishPublicKey(&stubKeySource{pub: pub}, path); err != nil {
		t.Fatalf("publishPublicKey: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("mtime changed (%s -> %s) — identical-contents path should not rewrite", before.ModTime(), after.ModTime())
	}
}

func TestPublishPublicKey_TightensLooseModeOnIdenticalContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pub")
	pub := "-----BEGIN PUBLIC KEY-----\nABCD\n-----END PUBLIC KEY-----\n"
	// Public key file already has correct contents but a non-0644 mode (e.g.
	// 0640 left over from a strict umask). Publishing should converge to 0644
	// without rewriting the bytes.
	if err := os.WriteFile(path, []byte(pub), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := publishPublicKey(&stubKeySource{pub: pub}, path); err != nil {
		t.Fatalf("publishPublicKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("perm = %o, want 0644", perm)
	}
}

func TestPublishPublicKey_RefusesMismatchedExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pub")
	if err := os.WriteFile(path, []byte("OLD KEY"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := publishPublicKey(&stubKeySource{pub: "NEW KEY"}, path)
	if err == nil {
		t.Fatal("expected refusal when published key differs from current keysource")
	}
	if !strings.Contains(err.Error(), "differs") {
		t.Errorf("error %q should mention the mismatch", err.Error())
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "OLD KEY" {
		t.Errorf("file should not have been overwritten; got %q", got)
	}
}

func TestPublishPublicKey_RefusesSymlinkAtPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.pub")
	link := filepath.Join(dir, "signing.key.pub")
	if err := os.WriteFile(target, []byte("anything"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}

	err := publishPublicKey(&stubKeySource{pub: "anything"}, link)
	if err == nil {
		t.Fatal("expected refusal when public-key path is a symlink")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error %q should mention non-regular file", err.Error())
	}
}

func TestPublishPublicKey_RequiresPath(t *testing.T) {
	if err := publishPublicKey(&stubKeySource{pub: "x"}, ""); err == nil {
		t.Fatal("expected error when PublicKeyPath is empty")
	}
}

func TestPublishPublicKey_PropagatesKeySourceError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key.pub")
	want := errors.New("kms unavailable")

	err := publishPublicKey(&stubKeySource{pubErr: want}, path)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if !errors.Is(err, want) {
		t.Errorf("expected wrapped %v, got %v", want, err)
	}
}

// TestPublishPublicKey_WithRealFileKeySource exercises the publishing path
// end-to-end against keysource.File so a future change to PublicKey()'s output
// shape (e.g. adding a header / changing PEM block type) breaks the publishing
// test loudly rather than silently producing files that cmd/agent-receipts
// can't parse.
func TestPublishPublicKey_WithRealFileKeySource(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.key.pub")

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	ks := keysource.NewFile(keyPath, "did:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.Teardown() })

	if err := publishPublicKey(ks, pubPath); err != nil {
		t.Fatalf("publishPublicKey: %v", err)
	}

	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("published file is not a PUBLIC KEY PEM: %s", pubPEM)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse published public key: %v", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		t.Fatalf("published key is %T, want ed25519.PublicKey", parsed)
	}
}

func TestTightenDBFiles_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	target := filepath.Join(dir, "elsewhere.db")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dbPath); err != nil {
		// Some environments (Windows without Developer Mode, restricted
		// containers) cannot create symlinks. Skip there — the symlink
		// rejection path can't be exercised without one.
		t.Skipf("os.Symlink unavailable in this environment: %v", err)
	}
	err := tightenDBFiles(dbPath)
	if err == nil {
		t.Fatal("expected tightenDBFiles to refuse a symlink at the DB path")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error %q should mention non-regular file", err.Error())
	}
}
