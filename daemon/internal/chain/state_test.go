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

