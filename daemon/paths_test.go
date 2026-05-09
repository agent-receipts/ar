package daemon

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultDBPath_UsesXDGDataHomeWhenAbsolute pins the spec-conformant
// branch: an absolute XDG_DATA_HOME wins over the home-based default.
func TestDefaultDBPath_UsesXDGDataHomeWhenAbsolute(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/srv/data")
	got := DefaultDBPath()
	if want := "/srv/data/agent-receipts/receipts.db"; got != want {
		t.Errorf("DefaultDBPath() = %q, want %q", got, want)
	}
}

// TestDefaultDBPath_FallsBackToHomeWhenXDGUnset pins the default the soak
// test relies on: ~/.local/share/agent-receipts/receipts.db on Linux/macOS.
func TestDefaultDBPath_FallsBackToHomeWhenXDGUnset(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	t.Setenv("XDG_DATA_HOME", "")
	got := DefaultDBPath()
	if want := "/home/test/.local/share/agent-receipts/receipts.db"; got != want {
		t.Errorf("DefaultDBPath() = %q, want %q", got, want)
	}
}

// TestDefaultDBPath_RefusesRelativeXDG ensures a relative XDG_DATA_HOME
// (which the spec says implementations must ignore) does not silently
// relocate the receipt store under the daemon's working directory.
func TestDefaultDBPath_RefusesRelativeXDG(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	t.Setenv("XDG_DATA_HOME", "relative/data")
	got := DefaultDBPath()
	if want := "/home/test/.local/share/agent-receipts/receipts.db"; got != want {
		t.Errorf("DefaultDBPath() = %q, want %q (relative XDG_DATA_HOME must be ignored)", got, want)
	}
}

func TestDefaultKeyPath_UsesXDGDataHomeWhenAbsolute(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/srv/data")
	got := DefaultKeyPath()
	if want := "/srv/data/agent-receipts/signing.key"; got != want {
		t.Errorf("DefaultKeyPath() = %q, want %q", got, want)
	}
}

func TestDefaultKeyPath_FallsBackToHomeWhenXDGUnset(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	t.Setenv("XDG_DATA_HOME", "")
	got := DefaultKeyPath()
	if want := "/home/test/.local/share/agent-receipts/signing.key"; got != want {
		t.Errorf("DefaultKeyPath() = %q, want %q", got, want)
	}
}

func TestDefaultKeyPath_RefusesRelativeXDG(t *testing.T) {
	t.Setenv("HOME", "/home/test")
	t.Setenv("XDG_DATA_HOME", "relative/data")
	got := DefaultKeyPath()
	if want := "/home/test/.local/share/agent-receipts/signing.key"; got != want {
		t.Errorf("DefaultKeyPath() = %q, want %q (relative XDG_DATA_HOME must be ignored)", got, want)
	}
}

// TestDefaultDBPath_AndKeyPath_ShareDir documents the invariant that the
// SQLite store and the signing key live under the same per-user directory.
// Both `--init` and Run rely on this — the operator only needs to back up
// one directory to capture both pieces of state.
func TestDefaultDBPath_AndKeyPath_ShareDir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/srv/data")
	if got, want := filepath.Dir(DefaultDBPath()), filepath.Dir(DefaultKeyPath()); got != want {
		t.Errorf("DB dir = %q, key dir = %q; should share parent", got, want)
	}
}

// TestDefaultPaths_PointAtAgentReceiptsSubdir guards against a future
// refactor accidentally dropping the per-app subdirectory and dumping
// receipts.db / signing.key directly into $XDG_DATA_HOME alongside other
// applications' data.
func TestDefaultPaths_PointAtAgentReceiptsSubdir(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/srv/data")
	for name, got := range map[string]string{"DB": DefaultDBPath(), "Key": DefaultKeyPath()} {
		if !strings.Contains(got, "/agent-receipts/") {
			t.Errorf("%s path %q missing /agent-receipts/ subdir", name, got)
		}
	}
}
