//go:build linux

package emitter

import (
	"os"
	"path/filepath"
)

// platformDefaultSocketPath returns the Linux default socket path.
//
// Linux relies on $XDG_RUNTIME_DIR (set per-user by systemd-logind for
// every desktop and service session) for the per-user case, falling
// back to /run/agentreceipts/events.sock for system-managed installs
// without an XDG runtime dir. Both ends of the IPC pair generally see
// the same value because systemd-logind is the canonical source — the
// env-divergence pattern that breaks the macOS default does not
// manifest on Linux in practice. Operators on headless boxes without
// systemd-logind should pin the path explicitly via
// AGENTRECEIPTS_SOCKET.
func platformDefaultSocketPath() string {
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		return filepath.Join(base, "agentreceipts", "events.sock")
	}
	return "/run/agentreceipts/events.sock"
}
