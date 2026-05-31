package audit

import (
	"context"
	"testing"
	"time"
)

func TestApproveBeforeTimeout(t *testing.T) {
	am := NewApprovalManager()

	done := make(chan ApprovalStatus, 1)
	go func() {
		done <- am.WaitForApproval(context.Background(), "req-1", 5*time.Second)
	}()

	// Give WaitForApproval time to register.
	time.Sleep(50 * time.Millisecond)

	if !am.Approve("req-1") {
		t.Fatal("Approve returned false")
	}

	result := <-done
	if result != ApprovalApproved {
		t.Errorf("expected WaitForApproval to return %q, got %q", ApprovalApproved, result)
	}
}

func TestDenyBeforeTimeout(t *testing.T) {
	am := NewApprovalManager()

	done := make(chan ApprovalStatus, 1)
	go func() {
		done <- am.WaitForApproval(context.Background(), "req-2", 5*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)

	if !am.Deny("req-2") {
		t.Fatal("Deny returned false")
	}

	result := <-done
	if result != ApprovalDenied {
		t.Errorf("expected WaitForApproval to return %q after deny, got %q", ApprovalDenied, result)
	}
}

func TestApprovalTimeout(t *testing.T) {
	am := NewApprovalManager()

	result := am.WaitForApproval(context.Background(), "req-3", 50*time.Millisecond)
	if result != ApprovalTimedOut {
		t.Errorf("expected WaitForApproval to return %q on timeout, got %q", ApprovalTimedOut, result)
	}
}

func TestApprovalContextCancel(t *testing.T) {
	am := NewApprovalManager()

	// A cancelled context unblocks the wait before the (long) timeout elapses
	// and reports ApprovalTimedOut so the caller fails the paused call safely.
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan ApprovalStatus, 1)
	go func() {
		done <- am.WaitForApproval(ctx, "req-cancel", time.Hour)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case result := <-done:
		if result != ApprovalTimedOut {
			t.Errorf("expected %q on context cancel, got %q", ApprovalTimedOut, result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForApproval did not return after context cancel")
	}
}

func TestApproveAfterTimeout(t *testing.T) {
	am := NewApprovalManager()

	// Let the wait expire.
	am.WaitForApproval(context.Background(), "req-4", 50*time.Millisecond)

	// Now try to approve — channel already consumed.
	if am.Approve("req-4") {
		t.Error("expected Approve to return false after timeout")
	}
}
