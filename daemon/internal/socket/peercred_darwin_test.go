//go:build darwin

package socket

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveExePath_Self resolves the running test binary's exe_path via
// proc_pidpath and verifies the syscall wiring works end-to-end. A correct
// result is the absolute path of the test binary go test compiled. Anything
// else means the SYS_PROC_INFO call number, flavor, or buffer-handling is
// wrong.
func TestResolveExePath_Self(t *testing.T) {
	got := resolveExePath(int32(os.Getpid()))
	if got == "" {
		t.Fatal("resolveExePath returned empty for the test process; SYS_PROC_INFO call likely misconfigured")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("resolveExePath = %q, want absolute path", got)
	}
	// Sanity: proc_pidpath returns a real on-disk path, not a /proc-style
	// symlink that disappears after exec.
	if _, err := os.Stat(got); err != nil {
		t.Errorf("resolveExePath returned %q which does not stat: %v", got, err)
	}
}
