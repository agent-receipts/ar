package audit

import (
	"sync"
	"time"
)

// ApprovalStatus describes the outcome of a pause/approval flow.
type ApprovalStatus string

const (
	ApprovalApproved   ApprovalStatus = "approved"
	ApprovalDenied     ApprovalStatus = "denied"
	ApprovalTimedOut   ApprovalStatus = "timed_out"
	ApprovalNoApprover ApprovalStatus = "no_approver"
)

// ApprovalManager handles pause/approve/deny flows for tool calls
// that require human approval before proceeding.
type ApprovalManager struct {
	mu      sync.Mutex
	pending map[string]chan bool
}

// NewApprovalManager creates a new ApprovalManager.
func NewApprovalManager() *ApprovalManager {
	return &ApprovalManager{
		pending: make(map[string]chan bool),
	}
}

// WaitForApproval blocks until the given approval ID is approved, denied, or
// the timeout elapses.
func (a *ApprovalManager) WaitForApproval(id string, timeout time.Duration) ApprovalStatus {
	ch := make(chan bool, 1)
	a.mu.Lock()
	a.pending[id] = ch
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()

	select {
	case approved := <-ch:
		if approved {
			return ApprovalApproved
		}
		return ApprovalDenied
	case <-time.After(timeout):
		return ApprovalTimedOut
	}
}

// Approve approves the pending request with the given ID.
// Returns false if the ID is not found or was already consumed.
func (a *ApprovalManager) Approve(id string) bool {
	a.mu.Lock()
	ch, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	a.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- true:
		return true
	default:
		return false
	}
}

// Deny denies the pending request with the given ID.
// Returns false if the ID is not found or was already consumed.
func (a *ApprovalManager) Deny(id string) bool {
	a.mu.Lock()
	ch, ok := a.pending[id]
	if ok {
		delete(a.pending, id)
	}
	a.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- false:
		return true
	default:
		return false
	}
}
