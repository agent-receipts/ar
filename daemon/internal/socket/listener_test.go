package socket

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListen_RefusesNonSocketPreexistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.sock")

	// Create a regular file at the socket path. A misconfigured
	// AGENTRECEIPTS_SOCKET pointing here must not silently delete it.
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected Listen to refuse a non-socket pre-existing file")
	}
	if !strings.Contains(err.Error(), "non-socket") {
		t.Errorf("error message %q should mention non-socket", err.Error())
	}

	// File must still be there — refusing implies not deleting.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Listen deleted the pre-existing file: %v", err)
	}
}
