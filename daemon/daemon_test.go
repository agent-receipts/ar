package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTightenDBFiles_TightensFresh0644(t *testing.T) {
	// SQLite creates DBs with umask-default 0644 on most systems. tightenDBFiles
	// must NOT refuse this case (we'd reject every fresh daemon startup) —
	// instead it should chmod down to 0640.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatalf("tightenDBFiles should chmod 0644 -> 0640, not refuse: %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("perm = %o, want 0640", got)
	}
}

func TestTightenDBFiles_TightensTo0640(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o660); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("perm = %o, want 0640", got)
	}
}

func TestTightenDBFiles_PreservesTighter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tightenDBFiles(dbPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 0600 must NOT be widened to 0640.
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("perm = %o, want 0600 (operator's tighter choice must be preserved)", got)
	}
}

func TestTightenDBFiles_NoErrorWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := tightenDBFiles(filepath.Join(dir, "does-not-exist.db")); err != nil {
		t.Errorf("absent DB should be a no-op, got: %v", err)
	}
}

func TestTightenDBFiles_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	target := filepath.Join(dir, "elsewhere.db")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dbPath); err != nil {
		// Some environments (Windows without Developer Mode, restricted
		// containers) cannot create symlinks. Skip there — the symlink
		// rejection path can't be exercised without one.
		t.Skipf("os.Symlink unavailable in this environment: %v", err)
	}
	err := tightenDBFiles(dbPath)
	if err == nil {
		t.Fatal("expected tightenDBFiles to refuse a symlink at the DB path")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("error %q should mention non-regular file", err.Error())
	}
}
