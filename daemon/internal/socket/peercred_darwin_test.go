//go:build darwin

package socket

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveExePath_Self verifies the SYS_PROC_INFO(PROC_PIDPATHINFO)
// syscall wiring end-to-end by resolving the running test binary's own
// exe_path. A non-empty absolute path pointing to the same file as
// os.Executable() means the call number, flavor, buffer pointer, and
// NUL-trimming are all correct. The os.SameFile comparison rather than
// string equality tolerates path-canonicalisation differences (e.g.
// /var → /private/var on macOS) and symlinks while still catching the
// regression a non-empty-only check misses: passing the wrong pid would
// produce a valid path that does not match the test process.
func TestResolveExePath_Self(t *testing.T) {
	got := resolveExePath(int32(os.Getpid()))
	if got == "" {
		// SYS_PROC_INFO may be restricted in sandboxed CI environments (e.g.
		// GitHub Actions macOS runners). An empty return is the documented
		// graceful-failure mode — the daemon still records pid/uid/gid. Skip
		// rather than fail so the test is not a permanent red on those runners.
		t.Skip("resolveExePath returned empty; SYS_PROC_INFO may be restricted in this environment")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("resolveExePath = %q, want absolute path", got)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("os.Stat(resolveExePath %q): %v", got, err)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("os.Stat(os.Executable %q): %v", want, err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Errorf("resolveExePath = %q is not the same file as os.Executable = %q", got, want)
	}
}
