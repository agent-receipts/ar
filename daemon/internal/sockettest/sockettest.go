// Package sockettest provides shared helpers for AF_UNIX socket tests.
//
// Helpers live here (a regular non-_test package) rather than in either of
// the two test files that need them so a single canonical implementation
// can be imported from both `daemon/internal/socket` (unit tests) and
// `daemon` (integration tests). Duplicated test helpers tend to drift, and
// the `shortSocketDir` flake we just chased through CI is exactly the kind
// of subtle path-length contract that should not exist in two places.
package sockettest

import (
	"os"
	"testing"
)

// ShortSocketDir returns a temp directory whose path is short enough to fit a
// socket filename within the 104-byte AF_UNIX sun_path limit on macOS.
// t.TempDir() on macOS GitHub Actions can return paths > 90 bytes, leaving
// no room for the socket filename and causing `bind: invalid argument`.
//
// We prefer /tmp when it exists (Linux, macOS); on platforms where it does
// not (e.g. Windows builders that exercise the build but not the AF_UNIX
// path) we fall back to os.TempDir() so the helper is still callable. The
// directory is removed via t.Cleanup, so callers do not need to RemoveAll
// themselves.
func ShortSocketDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ar*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
