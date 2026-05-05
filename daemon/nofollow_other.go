//go:build !unix

package daemon

// oNoFollow / oNonblock are no-ops on non-POSIX platforms. The daemon refuses
// to start on these platforms (see Run's platform gate), so these constants
// exist solely to keep the package compilable in cross-platform CI.
const (
	oNoFollow = 0
	oNonblock = 0
)

// isSymlinkLoop is unreachable on non-unix platforms — the daemon's runtime
// gate refuses to start there — and exists solely so daemon.go's symlink
// diagnostic compiles in cross-platform CI without referencing
// syscall.ELOOP, which is not defined on every Go port.
func isSymlinkLoop(_ error) bool { return false }
