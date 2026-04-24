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

// notifyWriter is an io.Writer that both captures output into a buffer and
// posts a signal on each Write. Tests block on notify instead of sleeping +
// polling so they stay reliable under slow / loaded runners.
type notifyWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
}

func newNotifyWriter() *notifyWriter {
	// Buffered so writes never block when the reader is between selects.
	return &notifyWriter{notify: make(chan struct{}, 16)}
}

func (n *notifyWriter) Write(p []byte) (int, error) {
	n.mu.Lock()
	nn, err := n.buf.Write(p)
	n.mu.Unlock()
	select {
	case n.notify <- struct{}{}:
	default:
	}
	return nn, err
}

func (n *notifyWriter) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.buf.String()
}

// waitForWrite blocks until at least one Write has happened since the last
// call (or the deadline passes). Returns the current buffer contents.
func (n *notifyWriter) waitForWrite(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case <-n.notify:
		return n.String()
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for write; buffer=%q", timeout, n.String())
		return ""
	}
}

// TestRunFollowLoopStreamsNewRows is the acceptance-criteria test from #216:
// start follow, insert a row, block until the write lands, assert content.
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

	startRowID, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}

	w := newNotifyWriter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, startRowID, store.Query{}, 10*time.Millisecond, false, w)
	}()

	// Insert is safe any time — an empty store yields no rows on early
	// ticks, so the watermark never advances past 0 until real rows land.
	storeFollowReceipt(t, s, kp, 1, "chain-follow", nil)

	out := w.waitForWrite(t, 2*time.Second)
	if !strings.Contains(out, "filesystem.file.read") {
		// Rare: the first write might be from something else. Wait once more.
		out = w.waitForWrite(t, 2*time.Second)
	}
	if !strings.Contains(out, "filesystem.file.read") {
		t.Fatalf("inserted receipt never appeared in follow output: %q", out)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("follow loop returned error: %v", err)
	}
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

	w := newNotifyWriter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, 0, q, 10*time.Millisecond, true, w)
	}()

	// chain-b is inserted first and must be filtered out; chain-a is
	// inserted second and must stream.
	storeFollowReceipt(t, s, kp, 1, "chain-b", nil)
	storeFollowReceipt(t, s, kp, 1, chainA, nil)

	// Wait until chain-a shows up (it may take a couple of write events
	// if chain-b somehow slipped through — which would then fail the check).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out := w.waitForWrite(t, 2*time.Second)
		if strings.Contains(out, chainA) {
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("follow loop returned error: %v", err)
			}
			final := w.String()
			if strings.Contains(final, "chain-b") {
				t.Fatalf("chain-b should have been filtered out: %q", final)
			}
			return
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("follow loop returned error: %v", err)
	}
	t.Fatalf("chain-a receipt never appeared in follow output: %q", w.String())
}
