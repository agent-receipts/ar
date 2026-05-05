//go:build unix

package daemon

import (
	"errors"
	"syscall"
)

// oNoFollow is OR'd into OpenFile flags so the open call refuses to follow a
// symlink at the target path itself. Combined with an O_EXCL on create paths
// and an fstat-after-open on read paths, this closes the TOCTOU window where
// an Lstat-then-Open pair could be tricked by an attacker who swaps the path
// between the two syscalls. Mirrors the same-named constant in
// internal/keysource so the two file-handling sites stay symmetrical.
const oNoFollow = syscall.O_NOFOLLOW

// oNonblock is OR'd into O_RDONLY opens of paths the daemon already Lstat'd
// as a regular file. On regular files O_NONBLOCK is a no-op on Linux/Darwin;
// on a FIFO it makes the read end open without parking the daemon waiting
// for a writer. That defends against a regular-file→FIFO swap between Lstat
// and Open — fstat-on-fd then rejects the non-regular file.
const oNonblock = syscall.O_NONBLOCK

// isSymlinkLoop reports whether err is the kernel's "would-follow-a-symlink"
// errno (ELOOP) returned when O_NOFOLLOW is set on an OpenFile against a
// symlink target. Wrapping the check in a build-tagged helper avoids
// referencing syscall.ELOOP from the cross-platform daemon.go — not every
// Go platform port defines that constant, so a direct reference would break
// `go build` on the !unix variant the daemon refuses to run on but that CI
// still compiles.
func isSymlinkLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
