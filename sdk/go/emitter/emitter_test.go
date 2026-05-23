//go:build integration && (linux || darwin)

// Tests run end-to-end against an in-process agent-receipts daemon.
//
// Build-tag-gated to:
//   - integration: the test imports github.com/agent-receipts/ar/daemon, but
//     sdk/go's published go.mod cannot require the daemon module — daemon
//     already requires sdk/go, and a back-edge would create an import cycle.
//     Under GOWORK=off (publish/verify path) the import would fail to resolve,
//     so the integration tag keeps the test out of the default `go test ./...`
//     run and pulls it in only via `go test -tags=integration` where go.work
//     wires the two modules locally. Matches sdk/go/integration_test.go and
//     sdk/go/cross_language_test.go which gate the same way for the same
//     reason.
//   - linux/darwin: the emitter speaks AF_UNIX and the daemon refuses to start
//     on other platforms — running these tests on a Windows builder would fail
//     at daemon.Run, not at the emitter we want to exercise.
package emitter_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// shortSocketDir returns a temp directory whose path is short enough that a
// socket filename inside it fits within the 104-byte AF_UNIX sun_path limit
// on macOS. t.TempDir() on macOS produces ~119-char paths under
// /var/folders/..., which exceed the limit and trip `bind: invalid argument`.
//
// Daemon-side tests use daemon/internal/sockettest.ShortSocketDir for the
// same reason; that helper lives in an internal package and is not
// importable from sdk/go, so this file inlines the same logic.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ar*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeTestKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

type daemonHandle struct {
	cfg      daemon.Config
	cancel   context.CancelFunc
	done     <-chan error
	stopOnce sync.Once
	stopErr  error
}

func startDaemon(t *testing.T, dir string) *daemonHandle {
	t.Helper()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(dir, "events.sock"),
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
		ChainID:              "emitter-test-chain",
		IssuerID:             "did:agent-receipts-daemon:emitter-test",
		VerificationMethodID: "did:agent-receipts-daemon:emitter-test#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	if _, err := os.Stat(cfg.KeyPath); os.IsNotExist(err) {
		writeTestKey(t, cfg.KeyPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("daemon exited before socket appeared: %v", err)
		case <-timeout.C:
			cancel()
			t.Fatalf("socket %s did not appear within 2s", cfg.SocketPath)
		case <-ticker.C:
			// poll again
		}
	}

	d := &daemonHandle{cfg: cfg, cancel: cancel, done: done}
	t.Cleanup(func() { d.stop(t) })
	return d
}

// stop shuts the daemon down deterministically and waits for Run to return.
// Idempotent via sync.Once so tests that explicitly stop a daemon mid-test
// (TestEmit_ReconnectAfterDaemonRestart) do not race the t.Cleanup
// registered by startDaemon — both paths converge on a single shutdown.
func (d *daemonHandle) stop(t *testing.T) {
	t.Helper()
	d.stopOnce.Do(func() {
		d.cancel()
		select {
		case err := <-d.done:
			if err != nil {
				t.Logf("daemon Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			d.stopErr = errors.New("daemon did not shut down within 3s")
		}
		// Confirm the socket is no longer accepting connections; a
		// "reconnect" test that ran against a still-listening socket
		// would silently pass without exercising the reconnect path.
		if conn, err := net.Dial("unix", d.cfg.SocketPath); err == nil {
			conn.Close()
			d.stopErr = errors.New("socket still accepting connections after stop")
		}
	})
	if d.stopErr != nil {
		t.Fatal(d.stopErr)
	}
}

func waitForReceiptCount(t *testing.T, dbPath, chainID string, want int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s, err := store.OpenReadOnly(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(chainID)
		if cerr := s.Close(); cerr != nil {
			t.Logf("close store: %v", cerr)
		}
		if err == nil && len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)", want, chainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// silentLogger discards every log line so the fire-and-forget drop logs
// do not pollute test output. Shared across tests rather than reallocated
// per-call — the handler has no per-test state.
var silentLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// TestEmit_FrameRoundTrip is the basic acceptance test: three events fired
// through the emitter materialise as three signed receipts in the daemon's
// chain, with monotonic sequence and the channel/tool/decision values the
// emitter sent.
func TestEmit_FrameRoundTrip(t *testing.T) {
	d := startDaemon(t, shortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	events := []emitter.Event{
		{Channel: "sdk", Tool: emitter.Tool{Server: "fixture", Name: "alpha"}, Decision: "allowed"},
		{Channel: "sdk", Tool: emitter.Tool{Server: "fixture", Name: "beta"}, Decision: "denied"},
		{Channel: "sdk", Tool: emitter.Tool{Name: "gamma"}, Decision: "pending"},
	}
	ctx := context.Background()
	for i, ev := range events {
		if err := em.Emit(ctx, ev); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, len(events), 5*time.Second)
	if len(receipts) != len(events) {
		t.Fatalf("got %d receipts, want %d", len(receipts), len(events))
	}

	wantTypes := []string{"sdk.fixture.alpha", "sdk.fixture.beta", "sdk.gamma"}
	wantStatus := []receipt.OutcomeStatus{receipt.StatusSuccess, receipt.StatusFailure, receipt.StatusPending}
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
		if r.CredentialSubject.Action.Type != wantTypes[i] {
			t.Errorf("receipt %d: action.type = %q, want %q", i, r.CredentialSubject.Action.Type, wantTypes[i])
		}
		if r.CredentialSubject.Action.ToolName != events[i].Tool.Name {
			t.Errorf("receipt %d: action.tool_name = %q, want %q", i, r.CredentialSubject.Action.ToolName, events[i].Tool.Name)
		}
		if r.CredentialSubject.Outcome.Status != wantStatus[i] {
			t.Errorf("receipt %d: outcome.status = %q, want %q", i, r.CredentialSubject.Outcome.Status, wantStatus[i])
		}
	}
}

// TestEmit_SessionIDStableAcrossEmits pins the OQ4 (ADR-0010, 2026-05-06)
// rule: session_id is allocated once at New() and reused across every Emit
// from the same emitter instance, never per-call. A regression that
// generated a fresh UUID per emit would fragment a logical agent session
// into N receipts with N session_ids.
func TestEmit_SessionIDStableAcrossEmits(t *testing.T) {
	d := startDaemon(t, shortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	wantSession := em.SessionID()
	if wantSession == "" {
		t.Fatal("emitter SessionID is empty; New() should generate a UUID v4")
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "noop"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, 3, 5*time.Second)
	for i, r := range receipts {
		if r.Issuer.SessionID != wantSession {
			t.Errorf("receipt %d: Issuer.SessionID = %q, want %q", i, r.Issuer.SessionID, wantSession)
		}
	}
}

// TestEmit_HashDeterminism guards that the emitter forwards Input bytes
// faithfully — without re-encoding — so that the daemon's RFC 8785
// canonicalisation is what actually determines parameters_hash. Two events
// whose Input is logically identical but differs in whitespace and key
// order MUST produce identical Action.ParametersHash. If the emitter ever
// starts re-marshalling Input, one of the two payloads would canonicalise
// to a different byte stream than the other, breaking this property.
func TestEmit_HashDeterminism(t *testing.T) {
	d := startDaemon(t, shortSocketDir(t))

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	// Same logical {a:1, b:2} payload, different key order, different
	// whitespace. RFC 8785 ignores both, so parameters_hash MUST match.
	inputs := []json.RawMessage{
		json.RawMessage(`{"a":1,"b":2}`),
		json.RawMessage(`{ "b":  2 , "a" : 1 }`),
	}
	ctx := context.Background()
	for i, in := range inputs {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "hash-fixture"},
			Input:    in,
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, len(inputs), 5*time.Second)
	if h0, h1 := receipts[0].CredentialSubject.Action.ParametersHash, receipts[1].CredentialSubject.Action.ParametersHash; h0 == "" || h1 == "" || h0 != h1 {
		t.Errorf("parameters_hash mismatch: receipt[0]=%q receipt[1]=%q (both must be non-empty and equal)", h0, h1)
	}
}

// TestEmit_FireAndForgetWhenDaemonDown enforces the core fire-and-forget
// contract from ADR-0010: an unreachable daemon MUST NOT block the agent.
// Emit returns nil within milliseconds when the configured socket path
// does not exist on disk.
func TestEmit_FireAndForgetWhenDaemonDown(t *testing.T) {
	dir := shortSocketDir(t)
	socketPath := filepath.Join(dir, "no-such-daemon.sock")

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(socketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	ctx := context.Background()
	start := time.Now()
	err = em.Emit(ctx, emitter.Event{
		Channel:  "sdk",
		Tool:     emitter.Tool{Name: "noop"},
		Decision: "allowed",
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Emit returned err = %v, want nil (fire-and-forget)", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Emit blocked for %v, want <50ms (fire-and-forget contract)", elapsed)
	}
}

// TestEmit_ReconnectAfterDaemonRestart proves the emitter survives a daemon
// outage: connection drops, daemon comes back, the next Emit (or one of
// the next few — ADR-0010 lets the emitter discover the broken conn at
// write time and re-dial on the following Emit) succeeds with the same
// session_id the emitter started with. Without lazy re-dial after a write
// failure, every post-restart Emit would silently drop forever.
func TestEmit_ReconnectAfterDaemonRestart(t *testing.T) {
	dir := shortSocketDir(t)
	d1 := startDaemon(t, dir)

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d1.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	wantSession := em.SessionID()
	ctx := context.Background()

	// Round 1: two events while the first daemon is up.
	for i := 0; i < 2; i++ {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "before-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("pre-restart Emit[%d]: %v", i, err)
		}
	}
	_ = waitForReceiptCount(t, d1.cfg.DBPath, d1.cfg.ChainID, 2, 5*time.Second)

	// Stop daemon 1, then start daemon 2 against the same DB / socket
	// path. The second daemon resumes the existing chain (ADR-0010 OQ2:
	// the daemon resumes from GetChainTail).
	d1.stop(t)
	d2 := startDaemon(t, dir)

	// Loop until reconnect lands a receipt. The emitter holds a stale
	// connection from daemon 1; the first Emit may fail at write time,
	// after which the conn is closed and the next Emit redials. Tolerating
	// a few attempts covers both orderings (immediate write failure
	// vs. delayed broken-pipe detection) without a hard-coded retry count.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := em.Emit(ctx, emitter.Event{
			Channel:  "sdk",
			Tool:     emitter.Tool{Name: "after-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("post-restart Emit: %v", err)
		}
		s, openErr := store.OpenReadOnly(d2.cfg.DBPath)
		if openErr != nil {
			t.Fatalf("open store: %v", openErr)
		}
		receipts, getErr := s.GetChain(d2.cfg.ChainID)
		s.Close()
		if getErr == nil && len(receipts) >= 3 {
			// Filter out daemon-synthesised events_dropped receipts: a
			// positive drop counter on the first post-restart frame causes
			// the daemon to prepend a synthetic receipt before the live one,
			// so receipts[2:] may start with it.
			var live []receipt.AgentReceipt
			for _, r := range receipts[2:] {
				if r.CredentialSubject.Action.Type != "agent_receipts.events_dropped" {
					live = append(live, r)
				}
			}
			if len(live) == 0 {
				// Only the synthetic receipt has arrived yet; wait for the live one.
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// Verify post-restart receipts carry the emitter's stable
			// session_id (OQ4 property: persists across daemon reconnects).
			for _, r := range live {
				if r.Issuer.SessionID != wantSession {
					t.Errorf("post-restart receipt session_id = %q, want %q", r.Issuer.SessionID, wantSession)
				}
				if r.CredentialSubject.Action.ToolName != "after-restart" {
					t.Errorf("post-restart receipt tool_name = %q, want %q", r.CredentialSubject.Action.ToolName, "after-restart")
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("emitter did not reconnect to the restarted daemon within 5s")
}

// TestEmit_ReturnsErrorAfterClose pins the contract that Close finalises
// the emitter: subsequent Emit calls return a clear error rather than
// silently dropping. A silent post-Close drop would mask use-after-close
// bugs in the caller (e.g. a deferred Emit firing after Close).
func TestEmit_ReturnsErrorAfterClose(t *testing.T) {
	dir := shortSocketDir(t)
	d := startDaemon(t, dir)

	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := em.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second Close is a no-op — Close is idempotent.
	if err := em.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}

	err = em.Emit(context.Background(), emitter.Event{
		Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit after Close returned nil, want error")
	}
}

// TestEmit_ValidatesEvent checks that Emit returns an error immediately for
// events the daemon would hard-reject, before any dial attempt. These are
// caller bugs, not transient failures, so they must not be silently dropped.
func TestEmit_ValidatesEvent(t *testing.T) {
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath("/nonexistent/events.sock"),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ctx := context.Background()
	cases := []struct {
		name string
		ev   emitter.Event
	}{
		{
			"missing channel",
			emitter.Event{Tool: emitter.Tool{Name: "noop"}, Decision: "allowed"},
		},
		{
			"missing tool.name",
			emitter.Event{Channel: "sdk", Decision: "allowed"},
		},
		{
			"empty decision",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}},
		},
		{
			"unknown decision",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "maybe"},
		},
		{
			"invalid Input JSON",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed", Input: json.RawMessage(`{bad}`)},
		},
		{
			"invalid Output JSON",
			emitter.Event{Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed", Output: json.RawMessage(`[unclosed`)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := em.Emit(ctx, tc.ev); err == nil {
				t.Error("Emit returned nil, want error")
			}
		})
	}
}

// TestEmit_WithSessionIDOverride pins the OQ4 host-id forwarding path:
// when WithSessionID supplies a non-empty value, every receipt carries
// that exact id rather than a freshly generated UUID. Mirrors the
// integration scenario where a host (Claude Code, an agent loop) owns
// the session identifier and the emitter must propagate it untouched.
func TestEmit_WithSessionIDOverride(t *testing.T) {
	d := startDaemon(t, shortSocketDir(t))

	const hostSession = "host-supplied-session-9f3a"
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(d.cfg.SocketPath),
		emitter.WithSessionID(hostSession),
		emitter.WithLogger(silentLogger),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = em.Close() })

	if got := em.SessionID(); got != hostSession {
		t.Fatalf("SessionID() = %q, want %q", got, hostSession)
	}

	if err := em.Emit(context.Background(), emitter.Event{
		Channel: "sdk", Tool: emitter.Tool{Name: "noop"}, Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	receipts := waitForReceiptCount(t, d.cfg.DBPath, d.cfg.ChainID, 1, 5*time.Second)
	if got := receipts[0].Issuer.SessionID; got != hostSession {
		t.Errorf("Issuer.SessionID = %q, want %q", got, hostSession)
	}
}
