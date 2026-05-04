//go:build unix

package daemon

import "syscall"

// applyRestrictiveUmask sets the process umask to 0o027 (no group-write,
// no world bits) and returns the previous umask. SQLite creates the WAL/SHM
// sidecars lazily — sometimes after tightenDBFiles has already run — so a
// loose umask would silently produce world-readable sidecars on first write.
// Setting umask process-wide closes that gap; chmod-based tightening at
// startup remains as belt-and-braces for files that already exist.
//
// Returns the previous umask so callers can restore on shutdown if desired
// (the daemon doesn't bother — it owns the process).
func applyRestrictiveUmask() int {
	return syscall.Umask(0o027)
}
