//go:build darwin

package socket

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveExePath_Self verifies the SYS_PROC_INFO(PROC_PIDPATHINFO)
// syscall wiring end-to-end by resolving the running test binary's own
// exe_path. A non-empty absolute path that stat's successfully means the
// call number, flavor, buffer pointer, and NUL-trimming are all correct.
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
