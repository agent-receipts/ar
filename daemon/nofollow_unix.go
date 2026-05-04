//go:build unix

package daemon

import "syscall"

// oNoFollow is OR'd into OpenFile flags so the open call refuses to follow a
// symlink at the target path itself. Combined with an O_EXCL on create paths
// and an fstat-after-open on read paths, this closes the TOCTOU window where
// an Lstat-then-Open pair could be tricked by an attacker who swaps the path
// between the two syscalls. Mirrors the same-named constant in
// internal/keysource so the two file-handling sites stay symmetrical.
const oNoFollow = syscall.O_NOFOLLOW
