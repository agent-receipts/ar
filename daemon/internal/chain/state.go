// Package chain owns the daemon's in-memory chain state — the next sequence
// number and the previous-receipt-hash for each chain id. The daemon is the
// sole writer to the receipts table, so this package's mutex is the only thing
// serialising chain-tail allocation across all emitter connections. Holding the
// state in one place is what fixes the concurrent-tail bug recorded on issue
// #236 (two mcp-proxy instances racing on the same chain tail).
package chain

import (
	"fmt"
	"sync"

	"github.com/agent-receipts/ar/sdk/go/store"
)

// State tracks the next-sequence and previous-hash for a single chain id. It
// is safe for concurrent use; allocators must call Allocate then either Commit
// (after a successful insert) or Rollback (after a failed insert) to release
// the lock with the right state. The mutex enforces single-allocation-at-a-
// time; a caller that forgets to Commit/Rollback before reallocating just
// blocks on the lock until something else releases it (and therefore never
// corrupts chain state).
//
// Phase 1 supports a single chain id per daemon process. Multi-chain support
// can grow this into a chainID-keyed map without changing callers.
type State struct {
	mu       sync.Mutex
	chainID  string
	nextSeq  int64
	prevHash *string // nil for the first receipt in a chain
}

// New returns a State for chainID with no prior receipts. Use NewFromTail when
// resuming an existing chain on daemon startup.
func New(chainID string) *State {
	return &State{chainID: chainID, nextSeq: 1, prevHash: nil}
}

// NewFromTail returns a State that resumes from the given chain tail. found
// reports whether the chain has prior receipts; when false, the daemon starts
// at sequence 1 with no prev_hash.
func NewFromTail(chainID string, tailSeq int64, tailHash string, found bool) *State {
	if !found {
		return New(chainID)
	}
	h := tailHash
	return &State{
		chainID:  chainID,
		nextSeq:  tailSeq + 1,
		prevHash: &h,
	}
}

// LoadFromStore opens the chain in s for chainID, reading the existing tail
// (if any) via GetChainTail. The daemon calls this once at startup.
func LoadFromStore(s store.ReceiptStore, chainID string) (*State, error) {
	seq, hash, found, err := s.GetChainTail(chainID)
	if err != nil {
		return nil, fmt.Errorf("load chain tail: %w", err)
	}
	return NewFromTail(chainID, seq, hash, found), nil
}

// ChainID reports the chain id this state owns.
func (s *State) ChainID() string { return s.chainID }

// NextSeq returns the sequence number a subsequent Allocate would return,
// without taking the allocation lock for any meaningful duration. Intended
// for diagnostics (e.g. startup log lines), not for the hot path.
func (s *State) NextSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeq
}

// Allocation is a reservation of the next (sequence, prev_hash) pair. Callers
// MUST eventually call Commit (with the freshly inserted receipt's hash) or
// Rollback. Failing to do so deadlocks the daemon — the underlying mutex stays
// held.
type Allocation struct {
	state    *State
	Sequence int64
	PrevHash *string // copy; nil for the first receipt
}

// Allocate reserves the next chain slot and returns it. The State's mutex is
// held until Commit or Rollback returns; callers must run the build/sign/insert
// pipeline synchronously while holding the allocation.
func (s *State) Allocate() Allocation {
	s.mu.Lock()
	var prev *string
	if s.prevHash != nil {
		v := *s.prevHash
		prev = &v
	}
	return Allocation{state: s, Sequence: s.nextSeq, PrevHash: prev}
}

// Commit advances the chain past this allocation. newHash is the hash of the
// just-inserted receipt and becomes the prev_hash for the next allocation.
func (a Allocation) Commit(newHash string) {
	if a.state == nil {
		panic("chain.Allocation: Commit on zero-value Allocation")
	}
	a.state.nextSeq = a.Sequence + 1
	h := newHash
	a.state.prevHash = &h
	a.state.mu.Unlock()
}

// Rollback releases the allocation without advancing the chain. Use this when
// the build/sign/insert pipeline fails after Allocate.
func (a Allocation) Rollback() {
	if a.state == nil {
		panic("chain.Allocation: Rollback on zero-value Allocation")
	}
	a.state.mu.Unlock()
}
