//go:build darwin

package daemon

import (
	"path/filepath"
	"testing"
)

// TestDefaultSocketPath_Darwin_HomeBased pins the macOS default introduced
// after issue #545: $XDG_DATA_HOME/agent-receipts/events.sock (defaulting
// to $HOME/.local/share). HOME is preserved across spawn contexts that
// strip TMPDIR — that property is the whole reason for the move. We
// run this only on darwin so the assertion is meaningful; the linux
// resolution lives elsewhere.
func TestDefaultSocketPath_Darwin_HomeBased(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/Users/testuser")

	got := DefaultSocketPath()
	want := "/Users/testuser/.local/share/agent-receipts/events.sock"
	if got != want {
		t.Errorf("DefaultSocketPath() = %q; want %q", got, want)
	}
}

// TestDefaultSocketPath_Darwin_IgnoresTMPDIR is the regression check
// for issue #545. The pre-fix code resolved the macOS default against
// TMPDIR, so a fake TMPDIR would show up in the result; the post-fix
// code must ignore TMPDIR entirely and stay anchored to HOME. If this
// test ever starts seeing /fake-tmpdir in the result, somebody has
// reintroduced the env-divergence bug.
func TestDefaultSocketPath_Darwin_IgnoresTMPDIR(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/Users/testuser")
	t.Setenv("TMPDIR", "/fake-tmpdir")

	got := DefaultSocketPath()
	want := "/Users/testuser/.local/share/agent-receipts/events.sock"
	if got != want {
		t.Errorf("DefaultSocketPath() = %q; want %q (must not consult TMPDIR on darwin)", got, want)
	}
}

// TestDefaultSocketPath_Darwin_RespectsXDGDataHome confirms the socket
// follows an explicit absolute XDG_DATA_HOME the same way the daemon's
// DB and signing key already do. Co-locating socket / DB / key under a
// single per-user directory keeps "back up one path" a true statement
// for operators.
func TestDefaultSocketPath_Darwin_RespectsXDGDataHome(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("XDG_DATA_HOME", "/srv/data")
	t.Setenv("HOME", "/Users/testuser")

	got := DefaultSocketPath()
	want := filepath.Join("/srv/data", "agent-receipts", "events.sock")
	if got != want {
		t.Errorf("DefaultSocketPath() = %q; want %q (XDG_DATA_HOME must win)", got, want)
	}
}

// TestDefaultSocketPath_Darwin_SharesDirWithDBAndKey documents the
// invariant that the socket, the receipt DB, and the signing key all
// live under the same per-user directory. The contract is asserted via
// the directory parents; if any of these three paths ever moves to a
// sibling location the operator backup story breaks silently.
func TestDefaultSocketPath_Darwin_SharesDirWithDBAndKey(t *testing.T) {
	t.Setenv("AGENTRECEIPTS_SOCKET", "")
	t.Setenv("XDG_DATA_HOME", "/srv/data")

	socketDir := filepath.Dir(DefaultSocketPath())
	dbDir := filepath.Dir(DefaultDBPath())
	keyDir := filepath.Dir(DefaultKeyPath())
	if socketDir != dbDir || dbDir != keyDir {
		t.Errorf("socket dir = %q, DB dir = %q, key dir = %q; all three must share parent", socketDir, dbDir, keyDir)
	}
}
