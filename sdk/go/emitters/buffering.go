package emitters

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// BufferingEmitterConfig configures [BufferingEmitter].
type BufferingEmitterConfig struct {
	// Inner is the downstream emitter that receives per-receipt deliveries
	// when the buffer flushes. Required.
	Inner Emitter

	// MaxBatchSize triggers a flush as soon as the buffer reaches this
	// size. Must be >= 1.
	MaxBatchSize int

	// FlushInterval triggers a flush after this duration of buffered
	// inactivity. Must be > 0.
	FlushInterval time.Duration
}

// BufferingEmitter wraps a downstream [Emitter] and buffers receipts in
// memory, flushing them on a configurable interval or batch size.
//
// The contract with the downstream emitter is PER-RECEIPT, not batched:
// a flush calls Inner.Emit once per buffered receipt.
//
// !!! CRASH-LOSS RISK !!!
// Buffered receipts are lost if the process exits before [BufferingEmitter.Flush]
// completes. This emitter is NOT suitable for environments where audit
// completeness is critical. Use a synchronous [HttpEmitter] (or a
// persistent WAL — tracked separately) when every receipt must reach the
// collector.
type BufferingEmitter struct {
	inner         Emitter
	maxBatchSize  int
	flushInterval time.Duration

	mu     sync.Mutex
	buffer []receipt.AgentReceipt
	timer  *time.Timer
	closed bool
}

// NewBuffering constructs a [BufferingEmitter] from the given config.
// Returns an error for invalid sizes/intervals so a misconfiguration is
// caught at construction rather than on the first Emit.
func NewBuffering(cfg BufferingEmitterConfig) (*BufferingEmitter, error) {
	if cfg.Inner == nil {
		return nil, errors.New("BufferingEmitter: Inner is required")
	}
	if cfg.MaxBatchSize < 1 {
		return nil, errors.New("BufferingEmitter: MaxBatchSize must be >= 1")
	}
	if cfg.FlushInterval <= 0 {
		return nil, errors.New("BufferingEmitter: FlushInterval must be > 0")
	}
	return &BufferingEmitter{
		inner:         cfg.Inner,
		maxBatchSize:  cfg.MaxBatchSize,
		flushInterval: cfg.FlushInterval,
	}, nil
}

// Emit appends r to the buffer and either flushes immediately (when
// MaxBatchSize is reached) or schedules a flush after FlushInterval.
func (b *BufferingEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("BufferingEmitter: closed")
	}
	b.buffer = append(b.buffer, r)
	if len(b.buffer) >= b.maxBatchSize {
		batch := b.takeBatchLocked()
		b.mu.Unlock()
		return b.deliver(ctx, batch)
	}
	b.scheduleTimerLocked()
	b.mu.Unlock()
	return nil
}

// Flush delivers every buffered receipt through the inner emitter.
// Resolves once each one has been delivered (or the inner emitter
// returned an error for one of them).
func (b *BufferingEmitter) Flush(ctx context.Context) error {
	b.mu.Lock()
	batch := b.takeBatchLocked()
	b.mu.Unlock()
	return b.deliver(ctx, batch)
}

// Close stops the interval timer and flushes the remaining buffer. After
// Close, subsequent Emit calls return an error. Safe to call multiple
// times.
func (b *BufferingEmitter) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	batch := b.takeBatchLocked()
	b.mu.Unlock()
	return b.deliver(ctx, batch)
}

// ----------------------------------------------------------------------

// takeBatchLocked drains the buffer and cancels any pending timer.
// Caller must hold b.mu.
func (b *BufferingEmitter) takeBatchLocked() []receipt.AgentReceipt {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	if len(b.buffer) == 0 {
		return nil
	}
	batch := b.buffer
	b.buffer = nil
	return batch
}

func (b *BufferingEmitter) scheduleTimerLocked() {
	if b.timer != nil {
		return
	}
	b.timer = time.AfterFunc(b.flushInterval, b.onTimer)
}

func (b *BufferingEmitter) onTimer() {
	b.mu.Lock()
	b.timer = nil
	if b.closed {
		b.mu.Unlock()
		return
	}
	batch := b.buffer
	b.buffer = nil
	b.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	// Swallow errors on the timer path so an internal goroutine never
	// crashes the host program on a downstream failure. Callers should
	// rely on Flush / Close for error surfacing.
	_ = b.deliver(context.Background(), batch)
}

func (b *BufferingEmitter) deliver(ctx context.Context, batch []receipt.AgentReceipt) error {
	for _, r := range batch {
		if err := b.inner.Emit(ctx, r); err != nil {
			return err
		}
	}
	return nil
}
