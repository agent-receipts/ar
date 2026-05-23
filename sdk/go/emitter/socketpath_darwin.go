//go:build darwin

package emitter

import (
	"os"
	"path/filepath"
)

// platformDefaultSocketPath returns the macOS default socket path: a
// HOME-based path that every process spawned by the same user resolves
// identically, regardless of inherited environment.
//
// Before issue #545 the macOS default lived under $TMPDIR (or /tmp as
// fallback). launchd assigns each user-session a per-user TMPDIR, but
// subprocesses spawned outside that session — most commonly MCP servers
// launched by GUI applications such as Claude Desktop — inherit no
// TMPDIR and silently land on /tmp, while the daemon launched from a
// shell keeps the per-user temp dir. The two ends could not find each
// other, no error surfaced, and zero receipts landed. Switching to
// $HOME (via xdgDataHome) closes that gap: $HOME is part of the bare
// minimum env that every spawn context preserves.
//
// The directory chosen is the same per-user directory the daemon
// already creates for its receipts.db and signing key, so backing up
// one path captures every piece of daemon state.
//
// Users who relied on TMPDIR to redirect the socket on macOS should
// switch to the AGENTRECEIPTS_SOCKET env var (or pass --socket) — that
// override has always taken precedence and is unaffected by this
// change.
func platformDefaultSocketPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "events.sock")
}

// xdgDataHome mirrors daemon.xdgDataHome so the emitter and the daemon
// resolve the same per-user directory without the emitter taking a
// runtime dependency on the daemon package (which would create an
// import cycle). The contract matches the daemon helper: honour an
// absolute XDG_DATA_HOME, ignore relative values per the XDG spec,
// otherwise fall back to $HOME/.local/share. Returns the empty string
// when neither source yields an absolute path so the caller can surface
// a clean "Config.SocketPath required" rather than emitting under a
// relative working directory.
func xdgDataHome() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome != "" && filepath.IsAbs(dataHome) {
		return dataHome
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".local", "share")
}
