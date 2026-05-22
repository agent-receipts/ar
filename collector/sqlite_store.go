package collector

import (
	"fmt"
	"strings"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// SQLiteStore is the production Store implementation backed by the shared
// sdk/go/store SQLite schema. The collector wraps store.Store with a
// duplicate-detection layer that maps SQLite UNIQUE-constraint violations to
// ErrDuplicate.
type SQLiteStore struct {
	inner *store.Store
}

// OpenSQLiteStore opens or creates a SQLite-backed collector store at the
// given path. Use ":memory:" for an in-process database (useful in tests but
// not durable across process restarts).
func OpenSQLiteStore(path string) (*SQLiteStore, error) {
	s, err := store.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	return &SQLiteStore{inner: s}, nil
}

func (s *SQLiteStore) Insert(r receipt.AgentReceipt, receiptHash string) error {
	// Look up first to give callers a stable ErrDuplicate before they observe
	// a raw driver error. Concurrent inserts with the same id can still race
	// past this check, so Insert's own error is the authoritative duplicate
	// signal — see below.
	existing, err := s.inner.GetByID(r.ID)
	if err != nil {
		return fmt.Errorf("lookup existing receipt: %w", err)
	}
	if existing != nil {
		return ErrDuplicate
	}

	if err := s.inner.Insert(r, receiptHash); err != nil {
		// modernc.org/sqlite reports UNIQUE-constraint violations as errors
		// whose string contains "UNIQUE constraint failed". The driver does
		// not export a typed error for this case, so a string-match is the
		// pragmatic choice. The receipts table has two UNIQUE constraints —
		// the PRIMARY KEY on id and idx_receipts_chain on (chain_id,
		// sequence) — so we additionally check that the constraint applied
		// here is on the id column, to avoid mis-reporting chain conflicts
		// as duplicates.
		if isUniqueIDViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("insert receipt: %w", err)
	}
	return nil
}

func isUniqueIDViolation(err error) bool {
	msg := err.Error()
	if !strings.Contains(msg, "UNIQUE constraint failed") {
		return false
	}
	// "UNIQUE constraint failed: receipts.id" is the id-collision case.
	return strings.Contains(msg, "receipts.id")
}

func (s *SQLiteStore) Exists(id string) (bool, error) {
	r, err := s.inner.GetByID(id)
	if err != nil {
		return false, fmt.Errorf("lookup receipt: %w", err)
	}
	return r != nil, nil
}

func (s *SQLiteStore) Close() error {
	return s.inner.Close()
}
