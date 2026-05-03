package keysource

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T, mode os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFile_InitSignVerify(t *testing.T) {
	path := writeTestKey(t, 0o600)
	ks := NewFile(path, "did:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	defer ks.Teardown()

	msg := []byte("hello world")
	sig, err := ks.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("sig len = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("public key PEM decode failed")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want ed25519.PublicKey", parsed)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature did not verify against returned public key")
	}
}

func TestFile_RejectsGroupReadablePerms(t *testing.T) {
	path := writeTestKey(t, 0o640)
	ks := NewFile(path, "did:test#k1")
	if err := ks.Init(); err == nil {
		t.Error("expected Init to reject 0640 key file")
	}
}

func TestFile_AllowsLooseWhenRequireOwnerOnlyIsFalse(t *testing.T) {
	path := writeTestKey(t, 0o644)
	ks := NewFile(path, "did:test#k1")
	ks.RequireOwnerOnly = false
	if err := ks.Init(); err != nil {
		t.Errorf("expected loose perms to be accepted with RequireOwnerOnly=false: %v", err)
	}
}

func TestFile_MissingPathErrors(t *testing.T) {
	ks := NewFile("/nonexistent/path/to/key.pem", "did:test#k1")
	if err := ks.Init(); err == nil {
		t.Error("expected Init to fail for missing key file")
	}
}

func TestFile_RotateNotImplemented(t *testing.T) {
	path := writeTestKey(t, 0o600)
	ks := NewFile(path, "did:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	if err := ks.Rotate(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Rotate err = %v, want ErrNotImplemented", err)
	}
}

func TestFile_SignBeforeInitErrors(t *testing.T) {
	ks := NewFile("/whatever", "did:test#k1")
	if _, err := ks.Sign([]byte("x")); err == nil {
		t.Error("expected Sign to fail before Init")
	}
}

func TestFile_TeardownClearsKey(t *testing.T) {
	path := writeTestKey(t, 0o600)
	ks := NewFile(path, "did:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	if err := ks.Teardown(); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Sign([]byte("x")); err == nil {
		t.Error("Sign after Teardown should fail")
	}
}
