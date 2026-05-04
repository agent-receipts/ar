//go:build !unix

package daemon

// applyRestrictiveUmask is a no-op on non-unix platforms. The daemon refuses
// to start outside Linux/macOS at runtime (see Run), so this only exists to
// keep the package compilable in cross-platform CI.
func applyRestrictiveUmask() int { return 0 }
