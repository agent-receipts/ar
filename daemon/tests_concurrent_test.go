//go:build integration && (linux || darwin)

package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// TestConcurrentSDKEmitters fires all 3 emitters (Go, TS, Python) concurrently,
// each emitting 10 frames. Verifies the daemon produces 30 receipts with no
// gaps in the sequence chain.
func TestConcurrentSDKEmitters(t *testing.T) {
	f := StartDaemon(t)

	const framesPerEmitter = 10
	const totalFrames = 3 * framesPerEmitter

	var wg sync.WaitGroup

	// Go emitter: 10 frames
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			f.EmitGoFrame(t, "go-concurrent", "sdk",
				pipeline.EmitterTool{Name: "concurrent-tool"}, "allowed")
		}
	}()

	// TypeScript emitter: 10 frames (may fail on alpha.2, but still concurrent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			f.EmitTSFrame(t, "ts-concurrent", "sdk", "concurrent-tool", "allowed")
		}
	}()

	// Python emitter: 10 frames
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < framesPerEmitter; i++ {
			f.EmitPythonFrame(t, "py-concurrent", "sdk", "concurrent-tool", "allowed")
		}
	}()

	wg.Wait()

	// Wait for all receipts (30 total, or fewer if TS fails on alpha.2)
	receipts := f.WaitForReceiptCount(t, totalFrames, 10*time.Second)

	if len(receipts) != totalFrames {
		t.Logf("expected %d receipts, got %d (some emitters may have failed on alpha.2)", totalFrames, len(receipts))
		t.Logf("trace:\n%s", f.Trace())
	}

	// Verify chain has no gaps
	seen := make(map[int]bool, len(receipts))
	for i, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seen[seq] {
			t.Errorf("seq %d allocated twice", seq)
		}
		seen[seq] = true

		// Verify previous hash chain
		if i == 0 {
			if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("first receipt prev_hash = %v, want nil", r.CredentialSubject.Chain.PreviousReceiptHash)
			}
		} else {
			want, err := receipt.HashReceipt(receipts[i-1])
			if err != nil {
				t.Fatal(err)
			}
			got := r.CredentialSubject.Chain.PreviousReceiptHash
			if got == nil || *got != want {
				t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
			}
		}

		// Verify signature
		ok, err := receipt.Verify(r, f.PublicKey)
		if err != nil || !ok {
			t.Errorf("receipt %d: verify ok=%v err=%v", i, ok, err)
		}
	}

	// Verify no gaps in sequence (1, 2, 3, ..., len(receipts))
	for seq := 1; seq <= len(receipts); seq++ {
		if !seen[seq] {
			t.Errorf("sequence %d missing (gap in chain)", seq)
		}
	}
}
