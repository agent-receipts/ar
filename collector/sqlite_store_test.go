package collector

import (
	"errors"
	"path/filepath"
	"testing"
)

func newSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	// Use a file path in the test tempdir rather than ":memory:" so that each
	// test gets a fresh database without sharing state through the driver's
	// shared in-memory cache.
	path := filepath.Join(t.TempDir(), "collector.db")
	s, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteStore_InsertAndExists(t *testing.T) {
	s := newSQLiteStore(t)
	r := testReceipt("urn:receipt:sqlite:1")

	if exists, err := s.Exists(r.ID); err != nil || exists {
		t.Fatalf("Exists before insert: exists=%v err=%v, want false/nil", exists, err)
	}

	if err := s.Insert(r, "sha256:abc"); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if exists, err := s.Exists(r.ID); err != nil || !exists {
		t.Fatalf("Exists after insert: exists=%v err=%v, want true/nil", exists, err)
	}
}

func TestSQLiteStore_InsertDuplicate(t *testing.T) {
	s := newSQLiteStore(t)
	r := testReceipt("urn:receipt:sqlite:dup")

	if err := s.Insert(r, "sha256:1"); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := s.Insert(r, "sha256:2")
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Insert: err=%v, want ErrDuplicate", err)
	}
}

func TestIsUniqueIDViolation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"id collision", errors.New("constraint failed: UNIQUE constraint failed: receipts.id"), true},
		{"chain collision", errors.New("UNIQUE constraint failed: idx_receipts_chain"), false},
		{"unrelated error", errors.New("disk I/O error"), false},
		{"nil-equivalent empty", errors.New(""), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueIDViolation(tc.err); got != tc.want {
				t.Fatalf("isUniqueIDViolation(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
