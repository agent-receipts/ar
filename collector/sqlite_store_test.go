package collector

import (
	"errors"
	"path/filepath"
	"sync"
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

	if err := s.Insert(r, []byte(`{}`), "sha256:abc"); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if exists, err := s.Exists(r.ID); err != nil || !exists {
		t.Fatalf("Exists after insert: exists=%v err=%v, want true/nil", exists, err)
	}
}

func TestSQLiteStore_InsertDuplicate(t *testing.T) {
	// Same id resubmitted: the cheap-path lookup hits and returns ErrDuplicate
	// before any INSERT attempt.
	s := newSQLiteStore(t)
	r := testReceipt("urn:receipt:sqlite:dup")

	if err := s.Insert(r, []byte(`{}`), "sha256:1"); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := s.Insert(r, []byte(`{}`), "sha256:2")
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Insert: err=%v, want ErrDuplicate", err)
	}
}

func TestSQLiteStore_ChainCollisionIsNotDuplicate(t *testing.T) {
	// Different ids but the same (chain_id, sequence) — this is a
	// chain-construction bug, not a safe retry. The collector must surface
	// it as a plain error (mapped to 500 by the server), NOT as ErrDuplicate.
	s := newSQLiteStore(t)
	r1 := testReceipt("urn:receipt:sqlite:chain-a")
	r2 := testReceipt("urn:receipt:sqlite:chain-b")
	// testReceipt fixes ChainID="chain-1", Sequence=0 — same for both.

	if err := s.Insert(r1, []byte(`{}`), "sha256:1"); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := s.Insert(r2, []byte(`{}`), "sha256:2")
	if err == nil {
		t.Fatal("second Insert with colliding chain+sequence: err=nil, want error")
	}
	if errors.Is(err, ErrDuplicate) {
		t.Fatalf("chain collision misclassified as ErrDuplicate: %v", err)
	}
}

// TestSQLiteStore_ConcurrentInserts exercises the duplicate-classification
// logic end-to-end against the real driver. modernc.org/sqlite's future
// error-message rewordings cannot break this: classification is driven by a
// re-lookup against the database, with the typed-error check as a fast path.
func TestSQLiteStore_ConcurrentInserts(t *testing.T) {
	s := newSQLiteStore(t)
	r := testReceipt("urn:receipt:sqlite:race")

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.Insert(r, []byte(`{}`), "sha256:r")
		}(i)
	}
	wg.Wait()

	var ok, dup int
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrDuplicate):
			dup++
		default:
			t.Fatalf("unexpected error from concurrent insert: %v", err)
		}
	}
	if ok != 1 || dup != 3 {
		t.Fatalf("concurrent inserts: ok=%d dup=%d, want 1/3", ok, dup)
	}
}

func TestIsPrimaryKeyViolation_TypedError(t *testing.T) {
	// isPrimaryKeyViolation is a fast-path optimisation that recognises a
	// typed *sqlite.Error with code SQLITE_CONSTRAINT_PRIMARYKEY. It must
	// return false for any plain Go error (including string-matched
	// constraint messages we no longer rely on), so that classification
	// falls through to the re-lookup path in Insert.
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"unrelated plain error", errors.New("disk I/O error"), false},
		{"empty plain error", errors.New(""), false},
		{"string-matching id message but not typed", errors.New("UNIQUE constraint failed: receipts.id"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPrimaryKeyViolation(tc.err); got != tc.want {
				t.Fatalf("isPrimaryKeyViolation(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
