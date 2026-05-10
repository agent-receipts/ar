//go:build integration && (linux || darwin)

package daemon

import (
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// TestSDKEmitterSingleFrame verifies the daemon processes a single frame
// from each SDK emitter (Go direct, TS subprocess, Python subprocess) and
// produces a verifiable receipt at sequence 1. The cases are run as
// subtests of one parent so each emitter still gets a fresh daemon (no
// cross-emitter chain interference) and reports independently in test
// output.
func TestSDKEmitterSingleFrame(t *testing.T) {
	cases := []struct {
		name      string
		sessionID string
		emit      func(t *testing.T, f *DaemonFixture)
	}{
		{
			name:      "go",
			sessionID: "go-test-session",
			emit: func(t *testing.T, f *DaemonFixture) {
				f.EmitGoFrame(t, "go-test-session", "sdk", pipeline.EmitterTool{Name: "test-tool"}, "allowed")
			},
		},
		{
			name:      "ts",
			sessionID: "ts-test-session",
			emit: func(t *testing.T, f *DaemonFixture) {
				f.EmitTSFrame(t, "ts-test-session", "sdk", "test-tool", "allowed")
			},
		},
		{
			name:      "python",
			sessionID: "py-test-session",
			emit: func(t *testing.T, f *DaemonFixture) {
				f.EmitPythonFrame(t, "py-test-session", "sdk", "test-tool", "allowed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := StartDaemon(t)

			tc.emit(t, f)

			receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)

			if len(receipts) != 1 {
				t.Fatalf("expected 1 receipt, got %d\ntrace:\n%s", len(receipts), f.Trace())
			}

			r := receipts[0]

			if r.CredentialSubject.Chain.Sequence != 1 {
				t.Errorf("sequence = %d, want 1", r.CredentialSubject.Chain.Sequence)
			}

			ok, err := receipt.Verify(r, f.PublicKey)
			if err != nil || !ok {
				t.Errorf("receipt verify failed: ok=%v err=%v", ok, err)
			}
		})
	}
}
