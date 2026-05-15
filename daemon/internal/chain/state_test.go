package chain

import (
	"sync"
	"testing"
)

func TestNew_StartsAtSequenceOne(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("first Allocate seq = %d, want 1", a.Sequence)
	}
	if a.PrevHash != nil {
		t.Errorf("first Allocate prev_hash = %v, want nil", a.PrevHash)
	}
}

func TestNewFromTail_NotFound(t *testing.T) {
	s := NewFromTail("c", 0, "", false)
	a := s.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 || a.PrevHash != nil {
		t.Errorf("not-found tail should start fresh: seq=%d prev=%v", a.Sequence, a.PrevHash)
	}
}

func TestNewFromTail_Resumes(t *testing.T) {
	s := NewFromTail("c", 7, "sha256:abc", true)
	a := s.Allocate()
	defer a.Rollback()
	if a.Sequence != 8 {
		t.Errorf("resume seq = %d, want 8", a.Sequence)
	}
	if a.PrevHash == nil || *a.PrevHash != "sha256:abc" {
		t.Errorf("resume prev = %v, want sha256:abc", a.PrevHash)
	}
}

func TestCommitAdvances(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	a.Commit("sha256:1")

	a2 := s.Allocate()
	defer a2.Rollback()
	if a2.Sequence != 2 {
		t.Errorf("after commit seq = %d, want 2", a2.Sequence)
	}
	if a2.PrevHash == nil || *a2.PrevHash != "sha256:1" {
		t.Errorf("after commit prev = %v, want sha256:1", a2.PrevHash)
	}
}

func TestRollbackDoesNotAdvance(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	a.Rollback()

	a2 := s.Allocate()
	defer a2.Rollback()
	if a2.Sequence != 1 {
		t.Errorf("after rollback seq = %d, want 1 (no advance)", a2.Sequence)
	}
	if a2.PrevHash != nil {
		t.Errorf("after rollback prev = %v, want nil", a2.PrevHash)
	}
}

// TestConcurrentAllocateSerialises is the regression-in-miniature for the bug
// in issue #236 comment 2: two concurrent allocators must each see distinct
// monotonic sequences, not the same one.
func TestConcurrentAllocateSerialises(t *testing.T) {
	s := New("c")
	const goroutines = 32
	const each = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	seen := make(chan int64, goroutines*each)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				a := s.Allocate()
				seen <- a.Sequence
				// Synthesize a unique-enough hash so Commit chains correctly.
				a.Commit("sha256:" + intToString(a.Sequence))
			}
		}()
	}
	wg.Wait()
	close(seen)

	got := make(map[int64]bool, goroutines*each)
	var maxSeq int64
	for s := range seen {
		if got[s] {
			t.Errorf("sequence %d allocated twice", s)
		}
		got[s] = true
		if s > maxSeq {
			maxSeq = s
		}
	}
	if int64(len(got)) != goroutines*each {
		t.Errorf("got %d distinct sequences, want %d", len(got), goroutines*each)
	}
	if maxSeq != int64(goroutines*each) {
		t.Errorf("maxSeq = %d, want %d (no gaps)", maxSeq, goroutines*each)
	}
}

func TestRollbackReleasesLock(t *testing.T) {
	// If Rollback didn't unlock, this would deadlock.
	s := New("c")
	for i := 0; i < 100; i++ {
		a := s.Allocate()
		a.Rollback()
	}
}

// TestRollbackAfterCommitIsNoOp documents the property pipeline.Process relies
// on: `defer alloc.Rollback()` is safe even when Commit ran first. Without
// idempotency this would panic with "unlock of unlocked mutex" or advance the
// chain twice.
func TestRollbackAfterCommitIsNoOp(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	a.Commit("sha256:1")
	a.Rollback() // must not panic, must not double-unlock

	a2 := s.Allocate()
	defer a2.Rollback()
	if a2.Sequence != 2 {
		t.Errorf("Rollback after Commit advanced or rewound the chain: seq = %d, want 2", a2.Sequence)
	}
}

func TestCommitAfterRollbackIsNoOp(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	a.Rollback()
	a.Commit("sha256:1") // must not panic, must not advance the chain

	a2 := s.Allocate()
	defer a2.Rollback()
	if a2.Sequence != 1 {
		t.Errorf("Commit after Rollback advanced the chain: seq = %d, want 1", a2.Sequence)
	}
	if a2.PrevHash != nil {
		t.Errorf("Commit after Rollback set prev_hash: %v, want nil", a2.PrevHash)
	}
}

func TestAllocatePair_AdjacentSequences(t *testing.T) {
	s := New("c")
	pair := s.AllocatePair()

	if pair.FirstSeq != 1 {
		t.Errorf("FirstSeq = %d, want 1", pair.FirstSeq)
	}
	if pair.FirstPrev != nil {
		t.Errorf("FirstPrev = %v, want nil", pair.FirstPrev)
	}

	second := pair.CommitFirst("hash-1")
	if second.Sequence != 2 {
		t.Errorf("second.Sequence = %d, want 2", second.Sequence)
	}
	if second.PrevHash == nil || *second.PrevHash != "hash-1" {
		t.Errorf("second.PrevHash = %v, want hash-1", second.PrevHash)
	}

	second.Commit("hash-2")

	// Next allocation must be at seq 3.
	next := s.Allocate()
	defer next.Rollback()
	if next.Sequence != 3 {
		t.Errorf("post-pair next.Sequence = %d, want 3", next.Sequence)
	}
	if next.PrevHash == nil || *next.PrevHash != "hash-2" {
		t.Errorf("post-pair next.PrevHash = %v, want hash-2", next.PrevHash)
	}
}

// TestAllocatePair_RollbackBeforeCommitFirst verifies that rolling back the
// pair before CommitFirst is called leaves the chain unchanged.
func TestAllocatePair_RollbackBeforeCommitFirst(t *testing.T) {
	s := New("c")
	pair := s.AllocatePair()
	pair.Rollback()

	// Chain must be unchanged: next Allocate should give seq 1.
	a := s.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("after Rollback, seq = %d, want 1", a.Sequence)
	}
}

// TestAllocatePair_RollbackAfterCommitFirst verifies that rolling back the
// second allocation (after CommitFirst) leaves the chain at seq 2 (first slot
// committed, second rolled back).
func TestAllocatePair_RollbackAfterCommitFirst(t *testing.T) {
	s := New("c")
	pair := s.AllocatePair()
	second := pair.CommitFirst("hash-1")
	second.Rollback() // second slot not committed

	// Chain is at seq 2 (first was committed by CommitFirst).
	a := s.Allocate()
	defer a.Rollback()
	if a.Sequence != 2 {
		t.Errorf("after CommitFirst+Rollback, seq = %d, want 2", a.Sequence)
	}
	if a.PrevHash == nil || *a.PrevHash != "hash-1" {
		t.Errorf("after CommitFirst+Rollback, prev_hash = %v, want hash-1", a.PrevHash)
	}
}

// TestAllocatePair_ConcurrentNoInterleave is the core regression: concurrent
// Allocate calls must not interleave with an active AllocatePair.
func TestAllocatePair_ConcurrentNoInterleave(t *testing.T) {
	s := New("c")

	// Hold a pair allocation and attempt concurrent Allocate from a goroutine.
	pair := s.AllocatePair()

	var goroutineSeq int64
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		a := s.Allocate() // must block until pair is fully committed
		goroutineSeq = a.Sequence
		a.Rollback()
		close(done)
	}()
	<-started

	// Complete the pair.
	second := pair.CommitFirst("h1")
	second.Commit("h2")

	<-done
	// Goroutine got seq 3 (after both pair slots committed).
	if goroutineSeq != 3 {
		t.Errorf("goroutine seq = %d, want 3 (pair held lock for both slots)", goroutineSeq)
	}
}

func TestDoubleRollbackIsNoOp(t *testing.T) {
	s := New("c")
	a := s.Allocate()
	a.Rollback()
	a.Rollback() // must not panic with "unlock of unlocked mutex"
}

// intToString avoids strconv import in a tight loop just to keep the file
// dependency-light. Used only for synthesizing unique commit hashes in tests.
func intToString(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

