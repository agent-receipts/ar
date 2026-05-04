//go:build unix

package keysource

import "syscall"

// oNoFollow is OR'd into the OpenFile flags so the open call refuses to
// follow a symlink at the key path itself. Combined with an fstat on the
// opened fd, this closes the TOCTOU window where an Lstat-then-ReadFile
// pair could be tricked by an attacker swapping the path between the two
// syscalls.
const oNoFollow = syscall.O_NOFOLLOW
