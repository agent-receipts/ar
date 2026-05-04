//go:build !unix

package daemon

// oNoFollow is a no-op on non-POSIX platforms. The daemon refuses to start on
// these platforms (see Run's platform gate), so this constant exists solely
// to keep the package compilable in cross-platform CI.
const oNoFollow = 0
