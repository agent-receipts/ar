//go:build integration && (linux || darwin)

package daemon

import (
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// TestGoEmitterSingleFrame verifies the daemon processes a single frame
// from the Go SDK's direct socket connection.
func TestGoEmitterSingleFrame(t *testing.T) {
	f := StartDaemon(t)

	f.EmitGoFrame(t, "go-test-session", "sdk", pipeline.EmitterTool{Name: "test-tool"}, "allowed")

	receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d\ntrace:\n%s", len(receipts), f.Trace())
	}

	r := receipts[0]

	// Verify basic receipt structure
	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("sequence = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}

	// Verify the receipt chain is valid
	ok, err := receipt.Verify(r, f.PublicKey)
	if err != nil || !ok {
		t.Errorf("receipt verify failed: ok=%v err=%v", ok, err)
	}
}

// TestTSEmitterSingleFrame verifies the daemon processes a single frame
// from the TypeScript SDK via subprocess. This test is expected to fail
// on alpha.2 due to the known TypeScript emitter bug.
func TestTSEmitterSingleFrame(t *testing.T) {
	f := StartDaemon(t)

	f.EmitTSFrame(t, "ts-test-session", "sdk", "test-tool", "allowed")

	receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d\ntrace:\n%s", len(receipts), f.Trace())
	}

	r := receipts[0]

	// Verify basic receipt structure
	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("sequence = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}

	// Verify the receipt chain is valid
	ok, err := receipt.Verify(r, f.PublicKey)
	if err != nil || !ok {
		t.Errorf("receipt verify failed: ok=%v err=%v", ok, err)
	}
}

// TestPythonEmitterSingleFrame verifies the daemon processes a single frame
// from the Python SDK via subprocess.
func TestPythonEmitterSingleFrame(t *testing.T) {
	f := StartDaemon(t)

	f.EmitPythonFrame(t, "py-test-session", "sdk", "test-tool", "allowed")

	receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d\ntrace:\n%s", len(receipts), f.Trace())
	}

	r := receipts[0]

	// Verify basic receipt structure
	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("sequence = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}

	// Verify the receipt chain is valid
	ok, err := receipt.Verify(r, f.PublicKey)
	if err != nil || !ok {
		t.Errorf("receipt verify failed: ok=%v err=%v", ok, err)
	}
}
