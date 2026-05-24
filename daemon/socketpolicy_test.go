package daemon

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// policyLogBuffer is a goroutine-safe bytes.Buffer for tests that read log output
// while a logger writes from another goroutine (log.Logger serializes its own
// writes, but a concurrent reader still races the buffer's internal state).
type policyLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *policyLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *policyLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *policyLogBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

// setupSocketEnv pins every environment variable that allowedSocketRoots and
// DefaultSocketPath consult to unique, test-controlled temp dirs, so the safe
// set is deterministic and host-independent rather than relying on whatever
// $XDG_RUNTIME_DIR / $TMPDIR the runner happens to set. (On Unix t.TempDir()
// itself usually lives under /tmp, but each is a distinct subdirectory, so the
// unsafeRoot path below — a different /tmp subdir — is never inside a safe
// root.) It also clears AGENTRECEIPTS_SOCKET so DefaultSocketPath resolves the
// platform default. Returns the per-platform directory a safe explicit override
// may live under.
func setupSocketEnv(t *testing.T) (safeRoot string) {
	t.Helper()
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	switch runtime.GOOS {
	case "linux":
		return os.Getenv("XDG_RUNTIME_DIR")
	case "darwin":
		return os.Getenv("TMPDIR")
	default:
		t.Skipf("socket-path policy test not meaningful on %s", runtime.GOOS)
		return ""
	}
}

// unsafeRoot returns a directory guaranteed to sit outside the safe set on
// Linux and macOS regardless of the test environment.
func unsafeRoot(t *testing.T) string {
	t.Helper()
	// /tmp is shared, world-traversable, and swept — the canonical unsafe
	// location from the issue's originating incident. setupSocketEnv pins the
	// safe roots to distinct temp subdirectories, so this sibling /tmp path is
	// never inside one and is reliably rejected.
	return filepath.Join("/tmp", "agent-receipts-538-"+t.Name())
}

func TestCheckSocketPath_DefaultIsSafe(t *testing.T) {
	setupSocketEnv(t)
	def := DefaultSocketPath()
	if def == "" {
		t.Fatal("DefaultSocketPath returned empty; test env did not resolve a default")
	}
	unsafe, err := checkSocketPath(def, false)
	if err != nil {
		t.Fatalf("default socket path %q rejected: %v", def, err)
	}
	if unsafe {
		t.Errorf("default socket path %q flagged unsafe; defaults must always be safe", def)
	}
}

func TestCheckSocketPath_AllowedExplicitPath(t *testing.T) {
	safeRoot := setupSocketEnv(t)
	p := filepath.Join(safeRoot, "agentreceipts", "events.sock")
	unsafe, err := checkSocketPath(p, false)
	if err != nil {
		t.Fatalf("explicit safe path %q rejected: %v", p, err)
	}
	if unsafe {
		t.Errorf("explicit safe path %q flagged unsafe", p)
	}
}

func TestCheckSocketPath_RejectsUnsafeWithoutFlag(t *testing.T) {
	setupSocketEnv(t)
	p := filepath.Join(unsafeRoot(t), "events.sock")
	unsafe, err := checkSocketPath(p, false)
	if err == nil {
		t.Fatalf("unsafe path %q accepted without --unsafe-socket-path", p)
	}
	if unsafe {
		t.Error("unsafe=true should not be returned alongside a refusal error")
	}
	if !strings.Contains(err.Error(), "unsafe-socket-path") {
		t.Errorf("error should name the escape hatch flag, got: %v", err)
	}
}

func TestCheckSocketPath_AcceptsUnsafeWithFlag(t *testing.T) {
	setupSocketEnv(t)
	p := filepath.Join(unsafeRoot(t), "events.sock")
	unsafe, err := checkSocketPath(p, true)
	if err != nil {
		t.Fatalf("unsafe path %q rejected even with --unsafe-socket-path: %v", p, err)
	}
	if !unsafe {
		t.Error("unsafe path with flag should report unsafe=true so the caller warns")
	}
}

func TestCheckSocketPath_RejectsTCPUnconditionally(t *testing.T) {
	setupSocketEnv(t)
	for _, addr := range []string{
		"127.0.0.1:9000",
		"localhost:9000",
		":9000",
		"[::1]:9000",
		"tcp://127.0.0.1:9000",
	} {
		// Even with --unsafe-socket-path, TCP must be refused (ADR-0010).
		for _, unsafeAllowed := range []bool{false, true} {
			unsafe, err := checkSocketPath(addr, unsafeAllowed)
			if err == nil {
				t.Errorf("TCP address %q accepted (unsafeAllowed=%v); ADR-0010 rejects TCP", addr, unsafeAllowed)
			}
			if unsafe {
				t.Errorf("TCP address %q returned unsafe=true; should be a hard error", addr)
			}
		}
	}
}

func TestLooksLikeTCPAddress(t *testing.T) {
	tcp := []string{"127.0.0.1:9000", "localhost:9000", ":9000", "[::1]:9000", "tcp://127.0.0.1:9000", "TCP://10.0.0.1:1"}
	for _, s := range tcp {
		if !looksLikeTCPAddress(s) {
			t.Errorf("looksLikeTCPAddress(%q) = false, want true", s)
		}
	}
	unixPaths := []string{
		"/run/agentreceipts/events.sock",
		"/tmp/x/events.sock",
		"events.sock",
		"./events.sock",
		"/var/run/foo:bar/events.sock", // colon in a dir name, but has a separator
	}
	for _, s := range unixPaths {
		if looksLikeTCPAddress(s) {
			t.Errorf("looksLikeTCPAddress(%q) = true, want false (unix path)", s)
		}
	}
}

// TestCheckSocketPath_SymlinkOutOfSafeSet covers the issue's symlink edge case:
// a path whose parent dir is a symlink pointing out of the safe set must be
// judged by its real target, not its apparent location.
func TestCheckSocketPath_SymlinkOutOfSafeSet(t *testing.T) {
	safeRoot := setupSocketEnv(t)
	outside := t.TempDir() // a fresh dir not under any safe root
	link := filepath.Join(safeRoot, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	p := filepath.Join(link, "events.sock")
	unsafe, err := checkSocketPath(p, false)
	if err == nil {
		t.Fatalf("symlink %q escaping the safe set was accepted: real target %q is unsafe", p, outside)
	}
	if unsafe {
		t.Error("unsafe=true should not accompany a refusal error")
	}
}

// TestCheckSocketPath_SymlinkLoopFailsClosed pins the fail-closed contract: a
// path the daemon cannot canonicalize (here a symlink cycle, which yields ELOOP
// rather than ENOENT) must be treated as unsafe, even though its apparent
// location is under a safe root. A previous version fell back to the literal
// unresolved path and would have judged this safe.
func TestCheckSocketPath_SymlinkLoopFailsClosed(t *testing.T) {
	safeRoot := setupSocketEnv(t)
	loopA := filepath.Join(safeRoot, "loopA")
	loopB := filepath.Join(safeRoot, "loopB")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatalf("symlink loopA: %v", err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatalf("symlink loopB: %v", err)
	}
	p := filepath.Join(loopA, "events.sock")
	unsafe, err := checkSocketPath(p, false)
	if err == nil {
		t.Fatalf("unresolvable path %q (symlink loop) was accepted; must fail closed", p)
	}
	if unsafe {
		t.Error("unsafe=true should not accompany a refusal error")
	}
}

func TestWarnUnsafeSocketPath_StartupAndPeriodic(t *testing.T) {
	var buf policyLogBuffer
	logger := log.New(&buf, "", 0)

	// Startup-only: interval <= 0 emits exactly one line and returns.
	warnUnsafeSocketPath(context.Background(), logger, "/tmp/x.sock", 0)
	if got := strings.Count(buf.String(), "level=warn"); got != 1 {
		t.Fatalf("startup-only warn emitted %d lines, want 1: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), "/tmp/x.sock") {
		t.Errorf("startup warning does not name the path: %q", buf.String())
	}

	// Periodic: a short interval must produce re-emissions beyond the startup
	// line, then stop promptly when ctx is cancelled.
	buf.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		warnUnsafeSocketPath(ctx, logger, "/tmp/x.sock", time.Millisecond)
		close(done)
	}()
	// Wait until at least the startup line plus a couple of ticks have landed.
	deadline := time.After(2 * time.Second)
	for {
		if strings.Count(buf.String(), "level=warn") >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected >=3 warn lines from periodic re-emission, got: %q", buf.String())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("warnUnsafeSocketPath did not return after ctx cancellation")
	}
}
