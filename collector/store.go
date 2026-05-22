// Package collector implements the reference HTTP collector that receives
// signed Agent Receipts from SDK HttpEmitters and persists them to a store.
//
// The collector is intentionally a dumb append-only sink. It does not sign,
// chain, sequence, or verify receipts — those are the SDK's responsibility on
// the emitting side and the auditor's responsibility on the consuming side.
// See ADR-0020 for the trust model.
package collector

import (
	"errors"
	"sync"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// ErrDuplicate is returned by Store.Insert when a receipt with the same id is
// already present. Callers map this to HTTP 409.
var ErrDuplicate = errors.New("collector: receipt id already exists")

// Store is the persistence contract for the collector. It is intentionally
// narrower than sdk/go/store.ReceiptStore — the collector does not query.
type Store interface {
	// Insert persists a signed receipt with its precomputed canonical hash.
	// Returns ErrDuplicate when the receipt id already exists. Implementations
	// MUST be safe for concurrent use.
	Insert(r receipt.AgentReceipt, receiptHash string) error

	// Exists reports whether a receipt with the given id is present.
	Exists(id string) (bool, error)

	// Close releases any resources held by the store.
	Close() error
}

// InMemoryStore is an in-process Store implementation suitable for tests and
// short-lived development use. It loses all data on process exit.
type InMemoryStore struct {
	mu       sync.RWMutex
	receipts map[string]storedReceipt
}

type storedReceipt struct {
	Receipt receipt.AgentReceipt
	Hash    string
}

// NewInMemoryStore returns an empty in-memory Store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{receipts: make(map[string]storedReceipt)}
}

func (s *InMemoryStore) Insert(r receipt.AgentReceipt, receiptHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.receipts[r.ID]; exists {
		return ErrDuplicate
	}
	s.receipts[r.ID] = storedReceipt{Receipt: r, Hash: receiptHash}
	return nil
}

func (s *InMemoryStore) Exists(id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.receipts[id]
	return ok, nil
}

func (s *InMemoryStore) Close() error { return nil }

// Len returns the number of receipts currently held. Test-only helper; not
// part of the Store interface.
func (s *InMemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receipts)
}

// Get returns the stored receipt for the given id, or false if absent.
// Test-only helper; not part of the Store interface.
func (s *InMemoryStore) Get(id string) (receipt.AgentReceipt, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sr, ok := s.receipts[id]
	if !ok {
		return receipt.AgentReceipt{}, "", false
	}
	return sr.Receipt, sr.Hash, true
}
