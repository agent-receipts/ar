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
		buf := make([]byte, n)
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
	em, err := New(
		WithSocketPath("/tmp/agentreceipts-emitter-no-such-socket.sock"),
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
