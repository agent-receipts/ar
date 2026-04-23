package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

func TestBuildApprovalDeniedMessageTimeout(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalTimedOut, 15*time.Second)

	for _, want := range []string{
		"timed out after 15s",
		"tool=create_pull_request",
		"rule=pause_high_risk",
		"risk=70",
		"approval_id=abc123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q to contain %q", got, want)
		}
	}
}

func TestBuildApprovalDeniedMessageExplicitDeny(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalDenied, 15*time.Second)

	if !strings.Contains(got, "denied by approval workflow") {
		t.Fatalf("expected explicit deny message, got %q", got)
	}
	if strings.Contains(got, "timed out") {
		t.Fatalf("explicit deny message should not mention timeout: %q", got)
	}
}

func TestDefaultDBPathUsesHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	got := defaultDBPath("audit.db")
	want := filepath.Join(home, ".agent-receipts", "audit.db")
	if got != want {
		t.Fatalf("defaultDBPath(audit.db) = %q, want %q", got, want)
	}
}

func TestDefaultDBPathFallsBackWhenHomeUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserHomeDir on Windows reads multiple env vars; fallback path is hard to force portably")
	}
	t.Setenv("HOME", "")

	got := defaultDBPath("audit.db")
	if got != "audit.db" {
		t.Fatalf("expected fallback to bare filename, got %q", got)
	}
}

func TestEnsureDBDirCreatesParent(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "nested", "sub", "audit.db")

	if err := ensureDBDir(dbPath); err != nil {
		t.Fatalf("ensureDBDir: %v", err)
	}

	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("parent is not a directory")
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("parent dir perm = %o, want 0700", perm)
		}
	}
}

func TestEnsureDBDirNoOpForBareFilename(t *testing.T) {
	if err := ensureDBDir("audit.db"); err != nil {
		t.Fatalf("ensureDBDir for bare filename should be a no-op, got %v", err)
	}
}
