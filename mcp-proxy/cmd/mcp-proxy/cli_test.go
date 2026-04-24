package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// storeFollowReceipt inserts a freshly signed receipt into the store.
// Helper for cmdList follow tests.
func storeFollowReceipt(t *testing.T, s *store.Store, kp receipt.KeyPair, seq int, chainID string, prevHash *string) string {
	t.Helper()
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test", Name: "test-agent"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow, ToolName: "read"},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: chainID},
	})
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
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
	return h
}

// TestRunFollowLoopStreamsNewRows is the acceptance-criteria test from #216:
// start follow, insert a row, see it in output.
func TestRunFollowLoopStreamsNewRows(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Start watermark on an empty store (rowid 0).
	startRowID, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		// Wrap buf behind a mutex so the test goroutine can read it safely
		// while the loop writes.
		done <- runFollowLoop(ctx, s, startRowID, store.Query{}, 20*time.Millisecond, false, &lockedWriter{w: &buf, mu: &mu})
	}()

	// Give the loop a moment to enter its first tick, then insert.
	time.Sleep(50 * time.Millisecond)
	storeFollowReceipt(t, s, kp, 1, "chain-follow", nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		out := buf.String()
		mu.Unlock()
		if strings.Contains(out, "filesystem.file.read") {
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("follow loop returned error: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	t.Fatalf("inserted receipt never appeared in follow output: %q", out)
}

// TestRunFollowLoopExitsOnContextCancel verifies Ctrl-C-style cancellation
// ends the loop promptly.
func TestRunFollowLoopExitsOnContextCancel(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, 0, store.Query{}, 20*time.Millisecond, false, &bytes.Buffer{})
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow loop returned error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow loop did not exit on context cancel")
	}
}

// TestRunFollowLoopHonoursFilters checks chain filter scoping: a chain-a watch
// should ignore chain-b inserts.
func TestRunFollowLoopHonoursFilters(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chainA := "chain-a"
	q := store.Query{ChainID: &chainA}

	var buf bytes.Buffer
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, 0, q, 20*time.Millisecond, true, &lockedWriter{w: &buf, mu: &mu})
	}()

	time.Sleep(50 * time.Millisecond)
	storeFollowReceipt(t, s, kp, 1, "chain-b", nil) // filtered out
	storeFollowReceipt(t, s, kp, 1, chainA, nil)    // should appear

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		out := buf.String()
		mu.Unlock()
		if strings.Contains(out, chainA) {
			cancel()
			<-done
			mu.Lock()
			final := buf.String()
			mu.Unlock()
			// chain-b must be absent — it was inserted first but doesn't match the filter.
			if strings.Contains(final, "chain-b") {
				t.Fatalf("chain-b should have been filtered out: %q", final)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("chain-a receipt never appeared in follow output")
}

// lockedWriter serializes Write calls so the test goroutine can safely
// snapshot output while the follow loop is writing.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
