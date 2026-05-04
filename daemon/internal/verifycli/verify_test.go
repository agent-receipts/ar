package verifycli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// fixtureChain writes a daemon-shaped DB at dbPath containing `count` valid
// signed receipts on chain `chainID`, and returns the matching public-key PEM
// path the verify CLI should be pointed at.
func fixtureChain(t *testing.T, dir, chainID string, count int) (dbPath, pubKeyPath string) {
	t.Helper()

	dbPath = filepath.Join(dir, "receipts.db")
	pubKeyPath = filepath.Join(dir, "signing.key.pub")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubKeyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevHash *string
	for i := 1; i <= count; i++ {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:     receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: chainID},
		})
		signed, err := receipt.Sign(unsigned, privPEM, "did:test#k1")
		if err != nil {
			t.Fatal(err)
		}
		h, err := receipt.HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return dbPath, pubKeyPath
}

func runOnce(t *testing.T, args []string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	// Empty env lookup so the test never accidentally inherits real
	// AGENTRECEIPTS_* values from the developer's shell.
	code = Run(args, &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestRun_VerifiesGoodChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, pubKeyPath := fixtureChain(t, dir, "chain-1", 3)

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitOK, stderr)
	}
	if !strings.Contains(stdout, "VALID (3 receipts)") {
		t.Errorf("stdout = %q, expected VALID with count", stdout)
	}
}

func TestRun_ReportsBrokenChain(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 2)

	// Use a *different* public key so signatures fail to verify.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKIXPublicKey(otherPub)
	wrongPubPath := filepath.Join(dir, "wrong.pub")
	if err := os.WriteFile(wrongPubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", wrongPubPath,
		"--chain-id", "chain-1",
	})
	if code != ExitChainBad {
		t.Fatalf("exit = %d, want %d (stderr=%s)", code, ExitChainBad, stderr)
	}
	if !strings.Contains(stdout, "BROKEN") || !strings.Contains(stdout, "BAD SIGNATURE") {
		t.Errorf("stdout = %q, expected BROKEN + BAD SIGNATURE lines", stdout)
	}
}

func TestRun_MissingPublicKeyIsUsageError(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := fixtureChain(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{
		"--db", dbPath,
		"--public-key", filepath.Join(dir, "does-not-exist.pub"),
		"--chain-id", "chain-1",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "read public key") {
		t.Errorf("stderr = %q, expected 'read public key' diagnostic", stderr)
	}
}

func TestRun_UnknownDBIsUsageError(t *testing.T) {
	dir := t.TempDir()
	_, pubKeyPath := fixtureChain(t, dir, "chain-1", 1)

	code, _, stderr := runOnce(t, []string{
		"--db", filepath.Join(dir, "no-such.db"),
		"--public-key", pubKeyPath,
		"--chain-id", "chain-1",
	})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
	if !strings.Contains(stderr, "open store") && !strings.Contains(stderr, "verify:") {
		t.Errorf("stderr = %q, expected open-store diagnostic", stderr)
	}
}

func TestRun_BadFlagIsUsageError(t *testing.T) {
	code, _, _ := runOnce(t, []string{"--bogus"})
	if code != ExitUsageError {
		t.Fatalf("exit = %d, want %d", code, ExitUsageError)
	}
}

func TestRun_HelpFlagExitsCleanly(t *testing.T) {
	code, _, stderr := runOnce(t, []string{"-h"})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d (asking for help is not an error)", code, ExitOK)
	}
	// The flag package writes the usage to fs.Output, which we redirected to
	// stderr. Sanity-check it lists at least one of our flags so a refactor
	// that drops the auto-generated usage block trips the test.
	if !strings.Contains(stderr, "--db") && !strings.Contains(stderr, "-db") {
		t.Errorf("stderr should mention --db; got %q", stderr)
	}
}
