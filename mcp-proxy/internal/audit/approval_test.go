package audit

import (
	"testing"
	"time"
)

func TestApproveBeforeTimeout(t *testing.T) {
	am := NewApprovalManager()

	done := make(chan ApprovalStatus, 1)
	go func() {
		done <- am.WaitForApproval("req-1", 5*time.Second)
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
		done <- am.WaitForApproval("req-2", 5*time.Second)
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

	result := am.WaitForApproval("req-3", 50*time.Millisecond)
	if result != ApprovalTimedOut {
		t.Errorf("expected WaitForApproval to return %q on timeout, got %q", ApprovalTimedOut, result)
	}
}

func TestApproveAfterTimeout(t *testing.T) {
	am := NewApprovalManager()

	// Let the wait expire.
	am.WaitForApproval("req-4", 50*time.Millisecond)

	// Now try to approve — channel already consumed.
	if am.Approve("req-4") {
		t.Error("expected Approve to return false after timeout")
	}
}
