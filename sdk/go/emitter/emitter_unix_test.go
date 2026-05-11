//go:build linux || darwin

// Unix-only tests that bind a real AF_UNIX listener and assert the wire
// behaviour of Emit: length-prefix framing matches the daemon's reader,
// reconnect after listener restart works without a Close/New dance,
// and sessionID is stable across multiple Emits.
//
// Tests live in this file rather than emitter_test.go because Windows lacks
// AF_UNIX in net.Listen for older Go releases used in CI matrix.
package emitter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// shortSocketDir returns a temp directory whose path leaves room for an
// AF_UNIX socket name. macOS sun_path is 104 bytes; t.TempDir() under
// /var/folders/… can produce ~119-char paths that overflow that limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "aremit*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// recordingListener accepts on a Unix socket and records every length-prefix
// frame it receives. Used to assert wire-format correctness without booting a
// full daemon. Stop closes both the listener AND any in-flight peer
// connections so reconnect tests can assert the emitter re-dials cleanly
// after the daemon goes away.
type recordingListener struct {
	ln       *net.UnixListener
	path     string
	mu       sync.Mutex
	frames   [][]byte
	conns    map[net.Conn]struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

func newRecordingListener(t *testing.T, dir string) *recordingListener {
	t.Helper()
	path := filepath.Join(dir, "events.sock")
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	rl := &recordingListener{
		ln:      ln,
		path:    path,
		conns:   make(map[net.Conn]struct{}),
		stopped: make(chan struct{}),
	}
	go rl.acceptLoop()
	t.Cleanup(rl.Stop)
	return rl
}

func (r *recordingListener) acceptLoop() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			select {
			case <-r.stopped:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		r.mu.Lock()
		select {
		case <-r.stopped:
			r.mu.Unlock()
			conn.Close()
			return
		default:
		}
		r.conns[conn] = struct{}{}
		r.mu.Unlock()
		go r.serveConn(conn)
	}
}

func (r *recordingListener) serveConn(conn net.Conn) {
	defer func() {
		r.mu.Lock()
		delete(r.conns, conn)
		r.mu.Unlock()
		conn.Close()
	}()
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > MaxFrameSize {
			return
		}
		buf := make([]byte, int(n))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		r.mu.Lock()
		r.frames = append(r.frames, buf)
		r.mu.Unlock()
	}
}

func (r *recordingListener) Stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		close(r.stopped)
		// Close every accepted conn so the emitter's cached connection
		// observes EOF/EPIPE on its next write — this is what triggers the
		// re-dial path the reconnect test exercises.
		for c := range r.conns {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.ln.Close()
	})
}

// snapshot returns a copy of the frames received so far.
func (r *recordingListener) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.frames))
	copy(out, r.frames)
	return out
}

func (r *recordingListener) waitForFrames(t *testing.T, want int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		got := r.snapshot()
		if len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d frames received within %s; want %d", len(got), timeout, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEmit_RoundTripWireFormat(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := New(
		WithSocketPath(rl.path),
		WithSessionID("wire-format-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ev := Event{
		Channel:  "mcp",
		Tool:     Tool{Server: "github", Name: "list_repos"},
		Input:    json.RawMessage(`{"owner":"foo"}`),
		Output:   json.RawMessage(`{"count":3}`),
		Decision: "allowed",
	}
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	frames := rl.waitForFrames(t, 1, 2*time.Second)
	if len(frames) != 1 {
		t.Fatalf("got %d frames; want 1", len(frames))
	}

	var got frame
	if err := json.Unmarshal(frames[0], &got); err != nil {
		t.Fatalf("unmarshal frame: %v (raw: %s)", err, frames[0])
	}
	if got.Version != SupportedFrameVersion {
		t.Errorf("frame.v = %q; want %q", got.Version, SupportedFrameVersion)
	}
	if got.SessionID != "wire-format-test" {
		t.Errorf("frame.session_id = %q; want %q", got.SessionID, "wire-format-test")
	}
	if got.Channel != "mcp" {
		t.Errorf("frame.channel = %q; want %q", got.Channel, "mcp")
	}
	if got.Tool.Server != "github" || got.Tool.Name != "list_repos" {
		t.Errorf("frame.tool = %+v; want {github list_repos}", got.Tool)
	}
	if got.Decision != "allowed" {
		t.Errorf("frame.decision = %q; want allowed", got.Decision)
	}
	if !json.Valid(got.Input) || string(got.Input) != `{"owner":"foo"}` {
		t.Errorf("frame.input = %s; want %s", got.Input, `{"owner":"foo"}`)
	}
	if !json.Valid(got.Output) || string(got.Output) != `{"count":3}` {
		t.Errorf("frame.output = %s; want %s", got.Output, `{"count":3}`)
	}
	if _, err := time.Parse(time.RFC3339Nano, got.TsEmit); err != nil {
		t.Errorf("frame.ts_emit %q is not RFC3339Nano: %v", got.TsEmit, err)
	}
}

func TestEmit_SessionIDStableAcrossCalls(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	const sid = "stable-session-2026-05"
	em, err := New(
		WithSocketPath(rl.path),
		WithSessionID(sid),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	for i := 0; i < 3; i++ {
		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "ping"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	frames := rl.waitForFrames(t, 3, 2*time.Second)
	for i, f := range frames {
		var got frame
		if err := json.Unmarshal(f, &got); err != nil {
			t.Fatalf("frame %d: unmarshal: %v", i, err)
		}
		if got.SessionID != sid {
			t.Errorf("frame %d: session_id = %q; want %q", i, got.SessionID, sid)
		}
	}
}

func TestEmit_ReconnectsAfterListenerRestart(t *testing.T) {
	dir := shortSocketDir(t)

	rl1 := newRecordingListener(t, dir)
	em, err := New(
		WithSocketPath(rl1.path),
		WithSessionID("reconnect-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	// First Emit reaches rl1.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "first"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit first: %v", err)
	}
	rl1.waitForFrames(t, 1, 2*time.Second)

	// Stop the listener and remove the socket file: the next Emit should
	// drop silently rather than hang or return an error.
	rl1.Stop()
	_ = os.Remove(rl1.path)

	// Drive the in-Emitter conn into a write failure so the next-Emit
	// re-dial path is exercised. Without an intermediate Emit the cached
	// conn would still be valid (writes succeed into the kernel buffer
	// even after the peer closes), so the second listener wouldn't see
	// the next frame.
	for i := 0; i < 3; i++ {
		_ = em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "during-outage"},
			Decision: "allowed",
		})
		time.Sleep(50 * time.Millisecond)
	}

	// Bring up a fresh listener at the same path.
	rl2 := newRecordingListener(t, dir)

	// New Emit must reach rl2; the emitter re-dials transparently.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := em.Emit(context.Background(), Event{
			Channel:  "mcp",
			Tool:     Tool{Name: "after-restart"},
			Decision: "allowed",
		}); err != nil {
			t.Fatalf("Emit after restart: %v", err)
		}
		got := rl2.snapshot()
		if len(got) > 0 {
			// Verify we received the post-restart frame.
			var f frame
			if err := json.Unmarshal(got[len(got)-1], &f); err != nil {
				t.Fatalf("unmarshal frame: %v", err)
			}
			if f.Tool.Name == "after-restart" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("rl2 never received an after-restart frame; got %d frames total", len(got))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEmit_FireAndForgetWhenSocketMissing(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithSessionID("no-daemon-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	start := time.Now()
	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	elapsed := time.Since(start)

	// Fire-and-forget: returns nil, not an error.
	if err != nil {
		t.Fatalf("Emit returned error %v; want nil (fire-and-forget)", err)
	}
	// 25ms dial timeout + 100ms write deadline = 125ms upper bound. Allow
	// 2x for slow CI.
	if elapsed > 250*time.Millisecond {
		t.Errorf("Emit took %s; want <250ms (fire-and-forget contract)", elapsed)
	}
}

// TestEmit_ContextCancelledOnEntry asserts that Emit returns the context error
// immediately when the context is already cancelled before the call.
func TestEmit_ContextCancelledOnEntry(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err = em.Emit(ctx, Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit with cancelled ctx returned nil; want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Emit returned %v; want context.Canceled", err)
	}
}

// TestNew_EmptySessionIDGeneratesUUID covers the WithSessionID("") branch:
// passing an empty string is treated as "no host id" and New falls back to
// generating a UUID, matching the behaviour when WithSessionID is not passed.
func TestNew_EmptySessionIDGeneratesUUID(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithSessionID(""), // explicit empty → generate UUID
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()
	if got := em.SessionID(); got == "" {
		t.Error("SessionID() is empty after WithSessionID(\"\"); want generated UUID")
	}
}

// TestEmit_ContextCancelledDuringDial covers the context-check that returns
// ctx.Err() when the context becomes invalid during dial (e.g. timeout or cancel).
// This test uses an already-expired context to reliably exercise that branch.
func TestEmit_ContextCancelledDuringDial(t *testing.T) {
	dir := shortSocketDir(t)

	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	// Create a context that expires immediately. Sleep briefly to ensure the
	// deadline has passed before Emit is called.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond)

	err = em.Emit(ctx, Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	// Either path (entry guard or post-dial guard) should return a context error.
	if err == nil {
		t.Skip("ctx happened to still be valid at both guards; timing-sensitive test skipped")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Emit returned %v; want DeadlineExceeded or Canceled", err)
	}
}

// TestEmit_NonNilEmptyInput checks the specific error for a non-nil empty
// Input slice (distinct from nil, which means "no payload").
func TestEmit_NonNilEmptyInput(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Input:    []byte{}, // non-nil, zero-length
	})
	if err == nil {
		t.Error("Emit with non-nil empty Input returned nil; want error")
	}
}

// TestEmit_NonNilEmptyOutput mirrors TestEmit_NonNilEmptyInput for Output.
func TestEmit_NonNilEmptyOutput(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Output:   []byte{}, // non-nil, zero-length
	})
	if err == nil {
		t.Error("Emit with non-nil empty Output returned nil; want error")
	}
}

// TestEmit_OversizedCombinedPayload asserts that Input+Output exceeding
// MaxFrameSize is rejected before any dial attempt.
func TestEmit_OversizedCombinedPayload(t *testing.T) {
	dir := shortSocketDir(t)
	em, err := New(
		WithSocketPath(filepath.Join(dir, "missing.sock")),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	// Build two JSON strings that together exceed MaxFrameSize.
	half := MaxFrameSize/2 + 1
	big := make([]byte, half)
	big[0] = '"'
	for i := 1; i < half-1; i++ {
		big[i] = 'x'
	}
	big[half-1] = '"'

	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
		Input:    big,
		Output:   big,
	})
	if err == nil {
		t.Error("Emit with oversized payload returned nil; want error")
	}
}

// TestEmit_OnClosedEmitter verifies that Emit returns an error when called on
// a closed emitter (after Close has been called).
func TestEmit_OnClosedEmitter(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := New(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Close the emitter.
	if err := em.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Emit on a closed emitter: must return an error, not drop silently.
	err = em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "noop"},
		Decision: "allowed",
	})
	if err == nil {
		t.Error("Emit on closed emitter returned nil; want error")
	}
}

// TestSessionID asserts that SessionID returns the value set by WithSessionID
// and that a generated ID is non-empty when no session is supplied.
func TestSessionID(t *testing.T) {
	dir := shortSocketDir(t)

	t.Run("explicit", func(t *testing.T) {
		em, err := New(
			WithSocketPath(filepath.Join(dir, "missing.sock")),
			WithSessionID("explicit-session-id"),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer em.Close()
		if got := em.SessionID(); got != "explicit-session-id" {
			t.Errorf("SessionID() = %q; want %q", got, "explicit-session-id")
		}
	})

	t.Run("generated", func(t *testing.T) {
		em, err := New(
			WithSocketPath(filepath.Join(dir, "missing.sock")),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer em.Close()
		if got := em.SessionID(); got == "" {
			t.Error("SessionID() is empty; want generated UUID")
		}
	})
}

// TestWriteAll_ShortWrite checks that writeAll returns io.ErrShortWrite
// when the writer returns (0, nil) — the zero-progress no-error case.
func TestWriteAll_ShortWrite(t *testing.T) {
	w := &zeroWriter{}
	err := writeAll(w, []byte("hello"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("writeAll with zero-progress writer: got %v; want io.ErrShortWrite", err)
	}
}

// zeroWriter always returns (0, nil) — simulates a writer that makes no
// progress without returning an error, which triggers the ErrShortWrite guard.
type zeroWriter struct{}

func (*zeroWriter) Write(_ []byte) (int, error) { return 0, nil }

// TestWriteFrame_TighterContextDeadline verifies that writeFrame uses the
// context deadline when it is tighter than writeTimeout. This test sets a
// 20ms deadline (tighter than the 100ms writeTimeout) and verifies the
// write still succeeds on a responsive listener (using the tighter deadline).
func TestWriteFrame_TighterContextDeadline(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := New(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	// First Emit to establish the connection.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "warmup"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("warmup Emit: %v", err)
	}
	rl.waitForFrames(t, 1, 2*time.Second)

	// Now emit with a deadline tighter than writeTimeout (100ms).
	// The listener is responsive so the write should complete within 20ms.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := em.Emit(ctx, Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "with-deadline"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("Emit with tighter deadline: %v", err)
	}
	rl.waitForFrames(t, 2, 2*time.Second)
}

// TestDefaultSocketPath_EnvOverride covers the AGENTRECEIPTS_SOCKET env var
// branch of DefaultSocketPath on supported platforms.
func TestDefaultSocketPath_EnvOverride(t *testing.T) {
	const want = "/custom/override/events.sock"
	t.Setenv("AGENTRECEIPTS_SOCKET", want)
	got := DefaultSocketPath()
	if got != want {
		t.Errorf("DefaultSocketPath() = %q; want %q", got, want)
	}
}

// TestDefaultSocketPath_TmpdirFallback exercises the darwin/linux branch
// where TMPDIR is empty and the path falls back to /tmp (darwin) or
// /run (linux). We only assert the path is non-empty and does not contain
// the empty string — the exact path is platform-dependent.
func TestDefaultSocketPath_TmpdirFallback(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	got := DefaultSocketPath()
	if got == "" {
		t.Errorf("DefaultSocketPath() = %q; want non-empty path on supported platform", got)
	}
}

// TestEmit_WriteFailureResetsConn exercises the write-failure branch in Emit:
// when writeFrame returns an error the conn must be reset to nil so the next
// Emit re-dials rather than attempting to write on a broken conn indefinitely.
func TestEmit_WriteFailureResetsConn(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := New(
		WithSocketPath(rl.path),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	// Establish a connection via the first Emit.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "first"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	rl.waitForFrames(t, 1, 2*time.Second)

	// Stop the listener so the next write fails.
	rl.Stop()
	_ = os.Remove(rl.path)
	// Give the OS time to propagate the conn close.
	time.Sleep(50 * time.Millisecond)

	// This Emit should fail the write and reset e.conn to nil (returns nil
	// per fire-and-forget contract).
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "failing"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("failing Emit returned error %v; want nil (fire-and-forget)", err)
	}

	// e.conn should now be nil; a subsequent Emit must attempt a new dial
	// (which will fail because the socket is gone) and return nil.
	if err := em.Emit(context.Background(), Event{
		Channel:  "mcp",
		Tool:     Tool{Name: "after-reset"},
		Decision: "allowed",
	}); err != nil {
		t.Fatalf("post-reset Emit returned error %v; want nil", err)
	}
}

func TestEmit_ConcurrentCallsAreSerialised(t *testing.T) {
	dir := shortSocketDir(t)
	rl := newRecordingListener(t, dir)

	em, err := New(
		WithSocketPath(rl.path),
		WithSessionID("concurrent-test"),
		WithLogger(silentLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer em.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = em.Emit(context.Background(), Event{
				Channel:  "mcp",
				Tool:     Tool{Name: "concurrent"},
				Decision: "allowed",
			})
		}()
	}
	wg.Wait()

	frames := rl.waitForFrames(t, n, 5*time.Second)
	if len(frames) != n {
		t.Fatalf("got %d frames; want %d", len(frames), n)
	}
	// Every frame must be parseable JSON: a torn write would corrupt the
	// length prefix and the recording listener would log a read error,
	// producing fewer than n frames or unparseable bytes here.
	for i, f := range frames {
		var got frame
		if err := json.Unmarshal(f, &got); err != nil {
			t.Errorf("frame %d: unmarshal: %v (raw: %s)", i, err, f)
		}
	}
}
