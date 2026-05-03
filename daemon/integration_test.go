//go:build integration

// Integration tests that exercise the daemon end-to-end: real Unix socket,
// real SQLite store, real signing key, and real OS peer-credential capture.
// Run with `go test -tags=integration ./...`.
package daemon_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func writeTestKey(t *testing.T, path string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func startDaemon(t *testing.T) (cfg daemon.Config, pubPEM string, cancel func()) {
	t.Helper()
	dir := t.TempDir()
	cfg = daemon.Config{
		SocketPath:           filepath.Join(dir, "events.sock"),
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		ChainID:              "it-chain",
		IssuerID:             "did:agent-receipts-daemon:integration",
		VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	pubPEM = writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	// Wait for the socket to appear (the daemon does some setup before Listen).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("daemon Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down within 3s")
		}
	})
	return cfg, pubPEM, cancel
}

func emitFrame(t *testing.T, socketPath string, frame pipeline.EmitterFrame) {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer conn.Close()
	body, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.WriteFrame(conn, body); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func waitForReceiptCount(t *testing.T, dbPath, chainID string, want int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(chainID)
		s.Close()
		if err == nil && len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)", want, chainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConcurrentEmittersSingleChain is the regression test for issue #236
// comment 2: two emitters firing concurrently must produce one monotonic
// chain with no gaps, no duplicate sequences, and no UNIQUE-index conflicts.
// The in-process design this replaces could not pass this test.
func TestConcurrentEmittersSingleChain(t *testing.T) {
	cfg, pubPEM, _ := startDaemon(t)

	const emitters = 4
	const perEmitter = 50
	total := emitters * perEmitter

	var wg sync.WaitGroup
	wg.Add(emitters)
	for e := 0; e < emitters; e++ {
		go func(emitterIdx int) {
			defer wg.Done()
			for i := 0; i < perEmitter; i++ {
				emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
					Version:   "1",
					TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
					SessionID: fmt.Sprintf("sess-%d", emitterIdx),
					Channel:   "mcp_proxy",
					Tool:      pipeline.EmitterTool{Server: "fixture", Name: "ping"},
					Decision:  "allowed",
				})
			}
		}(e)
	}
	wg.Wait()

	receipts := waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, total, 10*time.Second)

	if len(receipts) != total {
		t.Fatalf("got %d receipts, want %d", len(receipts), total)
	}

	seen := make(map[int]bool, total)
	for i, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seq != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d (gap or out-of-order)", i, seq, i+1)
		}
		if seen[seq] {
			t.Errorf("seq %d allocated twice", seq)
		}
		seen[seq] = true

		if i == 0 {
			if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("first receipt prev_hash = %v, want nil", r.CredentialSubject.Chain.PreviousReceiptHash)
			}
		} else {
			want, err := receipt.HashReceipt(receipts[i-1])
			if err != nil {
				t.Fatal(err)
			}
			got := r.CredentialSubject.Chain.PreviousReceiptHash
			if got == nil || *got != want {
				t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
			}
		}

		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt %d: verify ok=%v err=%v", i, ok, err)
		}
	}
}

// TestPeerCredCaptured verifies the daemon records the connecting process's
// OS-attested pid/uid in the receipt's peer-attestation slot. The agent's
// self-asserted identity is not consulted; this is the audit guarantee.
func TestPeerCredCaptured(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: "peer-fixture",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "noop"},
		Decision:  "allowed",
	})

	receipts := waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, 1, 5*time.Second)
	pd := receipts[0].CredentialSubject.Action.ParametersDisclosure

	wantPID := strconv.Itoa(os.Getpid())
	if pd["peer.pid"] != wantPID {
		t.Errorf("peer.pid = %q, want %q (OS-attested pid of test process)", pd["peer.pid"], wantPID)
	}
	wantUID := strconv.Itoa(os.Getuid())
	if pd["peer.uid"] != wantUID {
		t.Errorf("peer.uid = %q, want %q", pd["peer.uid"], wantUID)
	}

	switch pd["peer.platform"] {
	case "linux":
		if pd["peer.exe_path"] == "" {
			t.Error("Linux daemon should populate peer.exe_path from /proc/<pid>/exe")
		}
	case "darwin":
		// Phase 1 leaves exe_path empty on macOS.
	default:
		t.Errorf("unexpected peer.platform = %q", pd["peer.platform"])
	}
}

// TestResumesChainAfterRestart confirms GetChainTail wires through Run: a
// daemon started against an existing DB picks up the highest-sequence receipt
// and continues from there, rather than restarting at 1.
func TestResumesChainAfterRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")
	keyPath := filepath.Join(dir, "signing.key")
	socketPath := filepath.Join(dir, "events.sock")

	writeTestKey(t, keyPath)

	mkCfg := func() daemon.Config {
		return daemon.Config{
			SocketPath:           socketPath,
			DBPath:               dbPath,
			KeyPath:              keyPath,
			ChainID:              "resume-chain",
			IssuerID:             "did:agent-receipts-daemon:integration",
			VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
			Logger:               log.New(io.Discard, "", 0),
		}
	}

	runOnce := func(t *testing.T, frames int) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- daemon.Run(ctx, mkCfg()) }()

		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := os.Stat(socketPath); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("socket did not appear")
			}
			time.Sleep(10 * time.Millisecond)
		}

		for i := 0; i < frames; i++ {
			emitFrame(t, socketPath, pipeline.EmitterFrame{
				Version: "1", TsEmit: "2026-05-03T00:00:00Z",
				SessionID: "s", Channel: "sdk",
				Tool: pipeline.EmitterTool{Name: "noop"}, Decision: "allowed",
			})
		}
		// Give the daemon a moment to drain the in-flight frames before we
		// shut it down. Open the DB and poll until count is right.
		_ = waitForReceiptCount(t, dbPath, "resume-chain", frames, 5*time.Second)
		cancel()

		select {
		case err := <-done:
			if err != nil && !errors.Is(err, syscall.EINTR) {
				t.Logf("Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down")
		}
	}

	runOnce(t, 3)

	// Second run: against the same DB, frames should land at seq 4..6.
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tailSeq, _, _, err := s.GetChainTail("resume-chain")
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if tailSeq != 3 {
		t.Fatalf("after first run, tail seq = %d, want 3", tailSeq)
	}

	// Wait briefly so any pending socket cleanup completes.
	time.Sleep(50 * time.Millisecond)

	runOnce(t, 3) // each call expects frames new receipts; helper polls until count >= frames

	// At this point the helper polled until at least 3 receipts existed, but
	// the second run produced 3 *additional* ones, so the chain should be 6.
	receipts := waitForReceiptCount(t, dbPath, "resume-chain", 6, 5*time.Second)
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
}
