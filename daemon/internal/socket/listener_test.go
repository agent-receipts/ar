package socket

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocketDir returns a temp directory whose path is short enough to fit a
// socket filename within the 104-byte AF_UNIX sun_path limit on macOS.
// t.TempDir() on macOS GitHub Actions can return paths > 90 bytes, leaving
// no room for the socket filename. We prefer /tmp when it exists; on platforms
// where it does not (e.g. Windows), we fall back to os.TempDir().
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

func TestListen_RefusesNonSocketPreexistingFile(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	// Create a regular file at the socket path. A misconfigured
	// AGENTRECEIPTS_SOCKET pointing here must not silently delete it.
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected Listen to refuse a non-socket pre-existing file")
	}
	if !strings.Contains(err.Error(), "non-socket") {
		t.Errorf("error message %q should mention non-socket", err.Error())
	}

	// File must still be there — refusing implies not deleting.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Listen deleted the pre-existing file: %v", err)
	}
}

func TestListen_RefusesWhenAnotherDaemonIsLive(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	first, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = first.Serve(ctx) }()

	// Poll until a probe connect succeeds, instead of sleeping a fixed amount
	// (which is flaky on slow CI runners). 2s is generous; in practice the
	// listener is ready in microseconds on a quiet machine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, derr := net.DialTimeout("unix", path, 100*time.Millisecond); derr == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first listener did not become acceptable within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	second, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		second.Close()
		t.Fatal("expected Listen to refuse when another daemon is live on the same socket")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("error %q should mention an active daemon", err.Error())
	}
}
