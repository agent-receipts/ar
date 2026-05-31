package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

// TestServeApprovalsGracefulShutdown drives the real serveApprovals helper: it
// starts the approval server on an ephemeral port, confirms it accepts, cancels
// the context, and asserts the done channel closes (Serve returned via the
// ErrServerClosed clean-exit path) and the listener is closed afterwards.
func TestServeApprovalsGracefulShutdown(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := serveApprovals(ctx, ln, buildApprovalMux(approvals, token))

	// Confirm the server is actually accepting before shutting it down.
	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not accept connections within 2s: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancelling the context drives Shutdown; done closes once Serve returns.
	cancel()
	select {
	case <-done:
	case <-time.After(httpShutdownGrace + 2*time.Second):
		t.Fatal("serveApprovals did not signal done after context cancel")
	}

	// The listener must be closed: a fresh Accept on it fails immediately.
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after shutdown")
	}
}
