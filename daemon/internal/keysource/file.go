package keysource

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// File is a KeySource backed by a PEM-encoded Ed25519 private key on disk.
// Phase 1 uses this exclusively. Future ADR-0015 adapters (PKCS#11, cloud KMS)
// implement KeySource alongside this type.
type File struct {
	// Path is the PEM private-key path (PKCS#8). Required.
	Path string

	// VerificationMethodID is the DID URL embedded in proof.verificationMethod.
	// Required: receipts with an empty verification method aren't independently
	// verifiable.
	VerificationMethodID string

	// RequireOwnerOnly, when true, refuses to load a key whose file mode allows
	// group or world access. Defaults to true; tests can disable for tmpfile
	// fixtures whose perms are platform-controlled.
	RequireOwnerOnly bool

	priv   ed25519.PrivateKey
	pubPEM string
}

// NewFile returns an unloaded File. Call Init to read the key from disk.
func NewFile(path, verificationMethodID string) *File {
	return &File{Path: path, VerificationMethodID: verificationMethodID, RequireOwnerOnly: true}
}

// Init reads the PEM private key from f.Path and caches it.
func (f *File) Init() error {
	if f.Path == "" {
		return errors.New("keysource/file: Path is required")
	}
	if f.VerificationMethodID == "" {
		return errors.New("keysource/file: VerificationMethodID is required")
	}

	// Lstat (not Stat) so we observe a symlink at Path itself rather than
	// following it. A symlink-swap attack pointing at attacker-controlled
	// content would otherwise have its target's mode reported here. We also
	// require a regular file: a FIFO would block reads, a device file would
	// be wrong, and a directory makes no sense. Operators with legitimate
	// reasons to indirect (e.g. /etc/agentreceipts/signing.key being a
	// symlink to a Vault-managed file) should resolve the symlink before
	// pointing AGENTRECEIPTS_KEY at the result, or wait for the
	// ADR-0015 KMS adapters that don't read the key from disk at all.
	info, err := os.Lstat(f.Path)
	if err != nil {
		return fmt.Errorf("stat key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf(
			"keysource/file: refusing to load %s — not a regular file (mode %s); resolve symlinks and avoid FIFO/device/directory paths",
			f.Path, info.Mode(),
		)
	}
	if f.RequireOwnerOnly && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"keysource/file: refusing to load %s with permissions %o (any group/world bits set); chmod 0600",
			f.Path, info.Mode().Perm(),
		)
	}

	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("keysource/file: PEM decode failed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("keysource/file: key is %T, want ed25519.PrivateKey", parsed)
	}

	pub := priv.Public().(ed25519.PublicKey)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	f.priv = priv
	f.pubPEM = string(pubPEM)
	return nil
}

// Sign returns the raw 64-byte Ed25519 signature over message.
func (f *File) Sign(message []byte) ([]byte, error) {
	if f.priv == nil {
		return nil, errors.New("keysource/file: Init not called")
	}
	return ed25519.Sign(f.priv, message), nil
}

// PublicKey returns the PEM-encoded SPKI public key.
func (f *File) PublicKey() (string, error) {
	if f.pubPEM == "" {
		return "", errors.New("keysource/file: Init not called")
	}
	return f.pubPEM, nil
}

// VerificationMethod returns the configured verification-method ID.
func (f *File) VerificationMethod() string { return f.VerificationMethodID }

// Rotate is a stub. ADR-0015 specifies the rotation contract; Phase 1 does
// not implement it.
func (f *File) Rotate() error { return ErrNotImplemented }

// Teardown wipes the in-memory key.
func (f *File) Teardown() error {
	if f.priv != nil {
		for i := range f.priv {
			f.priv[i] = 0
		}
		f.priv = nil
	}
	f.pubPEM = ""
	return nil
}
