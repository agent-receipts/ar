package receipt

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// resetDevWarning redirects the dev-only warning to w and resets the
// once-latch so a test starts from a clean process-wide state. The original
// sink and a fresh latch are restored on cleanup.
func resetDevWarning(t *testing.T, w io.Writer) {
	t.Helper()
	prev := warnWriter
	warnWriter = w
	devWarnOnce = sync.Once{}
	t.Cleanup(func() {
		warnWriter = prev
		devWarnOnce = sync.Once{}
	})
}

func TestGeneratingKeyProviderThrowsInProduction(t *testing.T) {
	resetDevWarning(t, io.Discard)
	t.Setenv(productionEnvVar, "true")

	provider, err := NewGeneratingKeyProvider()
	if !errors.Is(err, ErrProductionKeyProvider) {
		t.Fatalf("expected ErrProductionKeyProvider, got %v", err)
	}
	if provider != nil {
		t.Error("expected nil provider when production guard fires")
	}
}

func TestGeneratingKeyProviderGeneratesOutsideProduction(t *testing.T) {
	resetDevWarning(t, io.Discard)
	t.Setenv(productionEnvVar, "")

	provider, err := NewGeneratingKeyProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	kp, err := provider.GetKeyPair()
	if err != nil {
		t.Fatalf("GetKeyPair: %v", err)
	}
	if kp.PublicKey == "" || kp.PrivateKey == "" {
		t.Fatal("expected a non-empty keypair")
	}

	// The keypair is stable for the lifetime of the provider.
	kp2, _ := provider.GetKeyPair()
	if kp2 != kp {
		t.Error("expected GetKeyPair to return a stable keypair")
	}

	// The generated keypair must produce a verifiable signature.
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatalf("Sign with generated key: %v", err)
	}
	valid, err := Verify(signed, kp.PublicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("expected the generated keypair to produce a valid signature")
	}
}

func TestGeneratingKeyProviderWarnsExactlyOncePerProcess(t *testing.T) {
	var buf bytes.Buffer
	resetDevWarning(t, &buf)
	t.Setenv(productionEnvVar, "")

	for range 3 {
		if _, err := NewGeneratingKeyProvider(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	got := strings.Count(buf.String(), "GeneratingKeyProvider is dev-only")
	if got != 1 {
		t.Errorf("expected exactly one dev-only warning, got %d", got)
	}
}

func TestGeneratingKeyProviderDoesNotWarnInProduction(t *testing.T) {
	var buf bytes.Buffer
	resetDevWarning(t, &buf)
	t.Setenv(productionEnvVar, "true")

	if _, err := NewGeneratingKeyProvider(); !errors.Is(err, ErrProductionKeyProvider) {
		t.Fatalf("expected ErrProductionKeyProvider, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no warning when the production guard fires, got %q", buf.String())
	}
}
