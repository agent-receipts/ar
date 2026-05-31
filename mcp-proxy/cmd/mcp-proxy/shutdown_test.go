package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

// waitAccepting blocks until the approval server on addr accepts a TCP
// connection, or fails the test after 2s. Confirms the listener is live before
// a test drives shutdown.
func waitAccepting(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not accept connections within 2s: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

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
	srv := serveApprovals(ctx, ln, buildApprovalMux(approvals, token))

	// Confirm the server is actually accepting before shutting it down.
	waitAccepting(t, ln.Addr().String())

	// Cancelling the context drives Shutdown; done closes once Serve returns.
	cancel()
	if err := waitForHTTPShutdown(srv); err != nil {
		t.Fatalf("clean ErrServerClosed shutdown must surface nil, got %v", err)
	}

	// The listener must be closed: a fresh Accept on it fails immediately.
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after shutdown")
	}
}

// TestServeApprovalsCleanCancelShutsDown covers Finding B: on the clean
// stdin-EOF path the proxy cancels a dedicated approval-server context (derived
// from the signal ctx) WITHOUT any OS signal. Cancelling that context alone
// must drive graceful shutdown — the done channel closes and the listener is
// torn down — so serve() never falls through while the HTTP goroutine is still
// accepting and racing the deferred emitter Close().
func TestServeApprovalsCleanCancelShutsDown(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// httpCtx models serve()'s dedicated approval-server context. The parent is
	// a plain Background context (no signal wiring), so the only thing that can
	// trigger shutdown here is httpCancel — exactly the clean-EOF path.
	httpCtx, httpCancel := context.WithCancel(context.Background())
	srv := serveApprovals(httpCtx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	// The clean-path trigger: cancel the dedicated context, then await teardown.
	httpCancel()
	if err := waitForHTTPShutdown(srv); err != nil {
		t.Fatalf("clean-path shutdown must surface nil, got %v", err)
	}

	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after clean-path shutdown")
	}
}

// TestServeApprovalsPropagatesServeError covers Finding A: a non-ErrServerClosed
// Serve error must be PROPAGATED back to the caller (via the handle's error
// channel, surfaced by waitForHTTPShutdown) rather than crashing the process
// with log.Fatalf, which would skip serve()'s deferred cleanup. We force Serve
// to fail by closing the listener out from under it before any shutdown is
// requested, then assert the error reaches the caller.
func TestServeApprovalsPropagatesServeError(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Never cancel the context: this isolates the Serve-error path from the
	// graceful ErrServerClosed path. Closing the listener makes srv.Serve return
	// a non-ErrServerClosed accept error, which the goroutine must forward.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := serveApprovals(ctx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	_ = ln.Close()

	serveErr := waitForHTTPShutdown(srv)
	if serveErr == nil {
		t.Fatal("expected serveApprovals to propagate the non-ErrServerClosed Serve error")
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatalf("ErrServerClosed must be treated as clean, not propagated: %v", serveErr)
	}
}
