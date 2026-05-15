//go:build integration && (linux || darwin)

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// TestConcurrentDaemonStartSameSocket verifies that when two daemon instances
// race to bind the same socket path, exactly one wins and the other returns a
// clear error containing "another daemon is already listening". This is the
// regression test for the "bind: address already in use" bug documented in
// issue #236 comment 1, where the second instance would crash or leave the
// socket in an inconsistent state.
func TestConcurrentDaemonStartSameSocket(t *testing.T) {
	fix := StartDaemon(t)

	// Attempt to start a second daemon at the SAME socket path. Give it the
	// same key (read-only reuse is fine — the second daemon will fail before
	// it needs to sign anything) and a separate writable DB so the only point
	// of contention is the socket.
	//
	// The second daemon MUST return a graceful error (not hang, not panic, not
	// remove the first daemon's socket). The exact error message is a contract
	// the socket package promises: "another daemon is already listening on …".
	dataDir2 := t.TempDir()
	cfg2 := fix.Config
	cfg2.DBPath = dataDir2 + "/receipts2.db"
	cfg2.PublicKeyPath = dataDir2 + "/signing.key.pub"

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- Run(ctx2, cfg2) }()

	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("second daemon started on an already-bound socket: expected error, got nil")
		}
		if !strings.Contains(err.Error(), "another daemon is already listening") {
			t.Errorf("unexpected error from second daemon: %v\n(want message containing 'another daemon is already listening')", err)
		}
	case <-time.After(5 * time.Second):
		cancel2()
		t.Fatal("second daemon did not exit within 5s; expected immediate error on duplicate socket bind")
	}

	// The first daemon must still be alive and serving.
	em, err := emitter.New(
		emitter.WithSocketPath(fix.Config.SocketPath),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		t.Fatalf("create emitter: %v", err)
	}
	defer em.Close()
	if err := em.Emit(context.Background(), emitter.Event{
		Channel:  "regression",
		Tool:     emitter.Tool{Name: "port-collision-test"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("first daemon no longer accepting after second daemon exit: %v", err)
	}
	fix.WaitForReceiptCount(t, 1, 5*time.Second)
}

// TestSandboxedEmitterViaDaemonSocket verifies that an emitter succeeds even
// when it has no write access to the canonical receipt-DB directory. This is
// the regression test for the pre-ADR-0010 architecture where the emitter
// wrote directly to SQLite: in a sandboxed process (read-only rootfs,
// container with mounted read-only volumes) the emitter would fail with a
// permission error when trying to create or open the database. After the
// daemon separation, the emitter only writes to the daemon's Unix socket and
// never touches the DB path itself.
func TestSandboxedEmitterViaDaemonSocket(t *testing.T) {
	fix := StartDaemon(t)

	// The emitter is constructed with only a socket path — no DB path whatsoever.
	// In the old architecture the emitter would have tried to open cfg.DBPath
	// (or the default ~/.agent-receipts/receipts.db) for writing. Here we
	// deliberately do NOT pass the DB path to the emitter; the emitter should
	// not need it and must succeed purely via the socket.
	em, err := emitter.New(
		emitter.WithSocketPath(fix.Config.SocketPath),
		emitter.WithSessionID("sandboxed-session"),
		emitter.WithLogger(slog.Default()),
	)
	if err != nil {
		t.Fatalf("emitter.New: %v", err)
	}
	defer em.Close()

	if err := em.Emit(context.Background(), emitter.Event{
		Channel:  "test",
		Tool:     emitter.Tool{Name: "sandboxed-tool"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit in read-only-DB scenario: %v (emitter should not need DB access)", err)
	}

	receipts := fix.WaitForReceiptCount(t, 1, 5*time.Second)
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	r := receipts[0]
	if r.CredentialSubject.Action.Type != "test.sandboxed-tool" {
		t.Errorf("action.type = %q, want test.sandboxed-tool", r.CredentialSubject.Action.Type)
	}
	if r.Issuer.SessionID != "sandboxed-session" {
		t.Errorf("issuer.session_id = %q, want sandboxed-session", r.Issuer.SessionID)
	}
}
