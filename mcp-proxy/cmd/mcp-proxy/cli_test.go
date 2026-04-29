package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// storeFollowReceipt inserts a freshly signed receipt into the store.
// Helper for cmdList follow tests.
func storeFollowReceipt(t *testing.T, s *store.Store, kp receipt.KeyPair, seq int, chainID string, prevHash *string) string {
	t.Helper()
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test", Name: "test-agent"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow, ToolName: "read"},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: chainID},
	})
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	h, err := receipt.HashReceipt(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(signed, h); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestWriteReceiptRows checks that writeReceiptRows renders SERVER, TOOL, and
// ACTION columns correctly, including the Target==nil legacy case.
func TestWriteReceiptRows(t *testing.T) {
	cases := []struct {
		name     string
		action   receipt.Action
		wantCols []string
		wantNot  []string
	}{
		{
			name: "with server and tool",
			action: receipt.Action{
				Type:      "data.api.write",
				RiskLevel: receipt.RiskMedium,
				ToolName:  "create_pull_request",
				Target:    &receipt.ActionTarget{System: "github"},
			},
			wantCols: []string{"github", "create_pull_request", "data.api.write", "medium"},
		},
		{
			name: "nil target (legacy receipt)",
			action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
				ToolName:  "read",
				Target:    nil,
			},
			wantCols: []string{"read", "filesystem.file.read", "low"},
		},
		{
			name: "long tool name truncated",
			action: receipt.Action{
				Type:      "data.api.read",
				RiskLevel: receipt.RiskLow,
				ToolName:  "searchJiraIssuesUsingJqlAndSomeExtraTextThatExceedsThirtyChars",
				Target:    &receipt.ActionTarget{System: "atlassian"},
			},
			wantCols: []string{"atlassian", "data.api.read"},
			wantNot:  []string{"searchJiraIssuesUsingJqlAndSomeExtraTextThatExceedsThirtyChars"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := receipt.AgentReceipt{
				ID: "urn:receipt:test-id",
				CredentialSubject: receipt.CredentialSubject{
					Action:  tc.action,
					Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
				},
			}
			var buf bytes.Buffer
			writeReceiptRows(&buf, []receipt.AgentReceipt{r})
			out := buf.String()
			for _, want := range tc.wantCols {
				if !strings.Contains(out, want) {
					t.Errorf("expected %q in output; got: %q", want, out)
				}
			}
			for _, notWant := range tc.wantNot {
				if strings.Contains(out, notWant) {
					t.Errorf("expected %q to be absent (truncated) in output; got: %q", notWant, out)
				}
			}
		})
	}
}

// notifyWriter is an io.Writer that both captures output into a buffer and
// posts a signal on each Write. Tests block on notify instead of sleeping +
// polling so they stay reliable under slow / loaded runners.
type notifyWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
}

func newNotifyWriter() *notifyWriter {
	// Buffered so writes never block when the reader is between selects.
	return &notifyWriter{notify: make(chan struct{}, 16)}
}

func (n *notifyWriter) Write(p []byte) (int, error) {
	n.mu.Lock()
	nn, err := n.buf.Write(p)
	n.mu.Unlock()
	select {
	case n.notify <- struct{}{}:
	default:
	}
	return nn, err
}

func (n *notifyWriter) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.buf.String()
}

// waitForWrite blocks until at least one Write has happened since the last
// call (or the deadline passes). Returns the current buffer contents.
func (n *notifyWriter) waitForWrite(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case <-n.notify:
		return n.String()
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for write; buffer=%q", timeout, n.String())
		return ""
	}
}

// TestValidateFollowFlags covers the CLI argument-validation path so a
// non-positive --interval with --follow fails fast instead of silently
// resetting. cmdList turns the returned error into an exit 2.
func TestValidateFollowFlags(t *testing.T) {
	cases := []struct {
		name     string
		follow   bool
		interval time.Duration
		wantErr  bool
	}{
		{"follow with zero interval", true, 0, true},
		{"follow with negative interval", true, -1 * time.Second, true},
		{"follow with positive interval", true, 100 * time.Millisecond, false},
		{"no follow, zero interval is fine", false, 0, false},
		{"no follow, negative interval is fine", false, -5 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFollowFlags(tc.follow, tc.interval)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "must be positive") {
				t.Errorf("error message missing \"must be positive\": %v", err)
			}
		})
	}
}

// TestRunFollowLoopStreamsNewRows is the acceptance-criteria test from #216:
// start follow, insert a row, block until the write lands, assert content.
func TestRunFollowLoopStreamsNewRows(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	startRowID, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}

	w := newNotifyWriter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, startRowID, store.Query{}, 10*time.Millisecond, false, w)
	}()

	// Insert is safe any time — an empty store yields no rows on early
	// ticks, so the watermark never advances past 0 until real rows land.
	storeFollowReceipt(t, s, kp, 1, "chain-follow", nil)

	out := w.waitForWrite(t, 2*time.Second)
	if !strings.Contains(out, "filesystem.file.read") {
		// Rare: the first write might be from something else. Wait once more.
		out = w.waitForWrite(t, 2*time.Second)
	}
	if !strings.Contains(out, "filesystem.file.read") {
		t.Fatalf("inserted receipt never appeared in follow output: %q", out)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("follow loop returned error: %v", err)
	}
}

// TestRunFollowLoopExitsOnContextCancel verifies Ctrl-C-style cancellation
// ends the loop promptly.
func TestRunFollowLoopExitsOnContextCancel(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, 0, store.Query{}, 20*time.Millisecond, false, &bytes.Buffer{})
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow loop returned error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow loop did not exit on context cancel")
	}
}

// TestRunFollowLoopHonoursFilters checks chain filter scoping: a chain-a watch
// should ignore chain-b inserts.
func TestRunFollowLoopHonoursFilters(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chainA := "chain-a"
	q := store.Query{ChainID: &chainA}

	w := newNotifyWriter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFollowLoop(ctx, s, 0, q, 10*time.Millisecond, true, w)
	}()

	// chain-b is inserted first and must be filtered out; chain-a is
	// inserted second and must stream.
	storeFollowReceipt(t, s, kp, 1, "chain-b", nil)
	storeFollowReceipt(t, s, kp, 1, chainA, nil)

	// Wait until chain-a shows up (it may take a couple of write events
	// if chain-b somehow slipped through — which would then fail the check).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out := w.waitForWrite(t, 2*time.Second)
		if strings.Contains(out, chainA) {
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("follow loop returned error: %v", err)
			}
			final := w.String()
			if strings.Contains(final, "chain-b") {
				t.Fatalf("chain-b should have been filtered out: %q", final)
			}
			return
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("follow loop returned error: %v", err)
	}
	t.Fatalf("chain-a receipt never appeared in follow output: %q", w.String())
}

func TestWritePrivateKeyFileCreatesWithCorrectPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	if err := writePrivateKeyFile(path, []byte("pem-data"), false); err != nil {
		t.Fatalf("writePrivateKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("permissions = %04o, want no group/world access", perm)
	} else if perm&0o600 != 0o600 {
		t.Errorf("permissions = %04o, want owner read/write", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "pem-data" {
		t.Errorf("content = %q, want %q", data, "pem-data")
	}
}

func TestWritePrivateKeyFileFailsIfExistsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	// Create the file first.
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := writePrivateKeyFile(path, []byte("new"), false)
	if err == nil {
		t.Fatal("expected error when file exists and force=false, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got %q", err.Error())
	}
}

func TestWritePrivateKeyFileOverwritesWithForce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	// Create an existing file with loose permissions to simulate the bad case.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := writePrivateKeyFile(path, []byte("new"), true); err != nil {
		t.Fatalf("writePrivateKeyFile with force: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("permissions after force overwrite = %04o, want no group/world access", perm)
	} else if perm&0o600 != 0o600 {
		t.Errorf("permissions after force overwrite = %04o, want owner read/write", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("content after force = %q, want %q", data, "new")
	}
}

func TestWritePrivateKeyFileFailsWhenParentDirectoryMissing(t *testing.T) {
	// cmdInit calls ensureDir before writePrivateKeyFile; this test confirms
	// writePrivateKeyFile itself returns an error if the directory is absent.
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "key.pem")

	err := writePrivateKeyFile(path, []byte("pem"), false)
	if err == nil {
		t.Fatal("expected error when parent directory does not exist")
	}
}

func TestWritePubKeyFileCreatesWithCorrectPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem.pub")

	if err := writePubKeyFile(path, []byte("pub-data"), false); err != nil {
		t.Fatalf("writePubKeyFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o444 != 0o444 {
		t.Errorf("permissions = %04o, want owner+group+world read (0644)", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "pub-data" {
		t.Errorf("content = %q, want %q", data, "pub-data")
	}
}

func TestWritePubKeyFileFailsIfExistsWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem.pub")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := writePubKeyFile(path, []byte("new"), false)
	if err == nil {
		t.Fatal("expected error when file exists and force=false, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got %q", err.Error())
	}
}

func TestWritePubKeyFileOverwritesWithForce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem.pub")

	// Existing file with restrictive permissions — force should fix them to 0644.
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := writePubKeyFile(path, []byte("new"), true); err != nil {
		t.Fatalf("writePubKeyFile with force: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o444 != 0o444 {
		t.Errorf("permissions after force overwrite = %04o, want at least 0444", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("content after force = %q, want %q", data, "new")
	}
}
