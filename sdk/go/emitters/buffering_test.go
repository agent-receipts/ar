package emitters_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/emitters"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// signalingEmitter notifies on every Emit so timer-driven tests don't have
// to poll.
type signalingEmitter struct {
	mu       sync.Mutex
	received []receipt.AgentReceipt
	ch       chan struct{}
}

func newSignalingEmitter(buf int) *signalingEmitter {
	return &signalingEmitter{ch: make(chan struct{}, buf)}
}

func (s *signalingEmitter) Emit(_ context.Context, r receipt.AgentReceipt) error {
	s.mu.Lock()
	s.received = append(s.received, r)
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
	return nil
}

func (s *signalingEmitter) Received() []receipt.AgentReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]receipt.AgentReceipt, len(s.received))
	copy(out, s.received)
	return out
}

func TestBufferingEmitter_RejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  emitters.BufferingEmitterConfig
	}{
		{
			"missing inner",
			emitters.BufferingEmitterConfig{MaxBatchSize: 1, FlushInterval: time.Second},
		},
		{
			"zero batch size",
			emitters.BufferingEmitterConfig{
				Inner: emitters.NewInMemory(), MaxBatchSize: 0, FlushInterval: time.Second,
			},
		},
		{
			"zero interval",
			emitters.BufferingEmitterConfig{
				Inner: emitters.NewInMemory(), MaxBatchSize: 1, FlushInterval: 0,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := emitters.NewBuffering(tc.cfg); err == nil {
				t.Fatalf("NewBuffering(%s) = nil err; want validation error", tc.name)
			}
		})
	}
}

func TestBufferingEmitter_FlushesOnBatchSize(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 3, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	for _, id := range []string{"r1", "r2"} {
		if err := buf.Emit(ctx, fakeReceipt(id)); err != nil {
			t.Fatalf("Emit(%s): %v", id, err)
		}
	}
	if got := inner.Received(); len(got) != 0 {
		t.Fatalf("flushed early: %v", got)
	}
	if err := buf.Emit(ctx, fakeReceipt("r3")); err != nil {
		t.Fatalf("Emit(r3): %v", err)
	}
	got := inner.Received()
	if len(got) != 3 {
		t.Fatalf("inner.Received() = %v; want 3 entries", got)
	}
}

func TestBufferingEmitter_FlushesOnInterval(t *testing.T) {
	sig := newSignalingEmitter(4)
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: sig, MaxBatchSize: 100, FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	if err := buf.Emit(context.Background(), fakeReceipt("r1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-sig.ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("interval flush did not fire within 2s")
	}
	if got := sig.Received(); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("received = %v; want [r1]", got)
	}
}

func TestBufferingEmitter_ExplicitFlushDrainsBuffer(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 100, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	_ = buf.Emit(ctx, fakeReceipt("r2"))
	if err := buf.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got := inner.Received()
	if len(got) != 2 {
		t.Fatalf("inner.Received() = %v; want 2 entries", got)
	}
}

func TestBufferingEmitter_PerReceiptContract(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 4, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		_ = buf.Emit(ctx, fakeReceipt(id))
	}
	// Each receipt arrives individually at the downstream — not batched.
	if got := inner.Received(); len(got) != 4 {
		t.Fatalf("inner.Received() = %v; want 4 separate entries", got)
	}
}

func TestBufferingEmitter_FlushSurfacesDownstreamError(t *testing.T) {
	boom := errors.New("downstream failed")
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner:         &failingEmitter{err: boom},
		MaxBatchSize:  100,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close(context.Background()) })

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	if err := buf.Flush(ctx); !errors.Is(err, boom) {
		t.Fatalf("Flush err = %v; want %v", err, boom)
	}
}

func TestBufferingEmitter_CloseDrainsAndBlocksEmit(t *testing.T) {
	inner := emitters.NewInMemory()
	buf, err := emitters.NewBuffering(emitters.BufferingEmitterConfig{
		Inner: inner, MaxBatchSize: 100, FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBuffering: %v", err)
	}

	ctx := context.Background()
	_ = buf.Emit(ctx, fakeReceipt("r1"))
	if err := buf.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := inner.Received(); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("inner.Received() = %v; want [r1]", got)
	}
	if err := buf.Emit(ctx, fakeReceipt("r2")); err == nil {
		t.Errorf("Emit after Close: nil err; want closed error")
	}
}
