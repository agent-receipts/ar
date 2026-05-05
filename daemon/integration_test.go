//go:build integration && (linux || darwin)

// Integration tests that exercise the daemon end-to-end: real Unix socket,
// real SQLite store, real signing key, and real OS peer-credential capture.
// Run with `go test -tags=integration ./...`.
//
// The build tag also gates on linux || darwin: the daemon's runtime gate
// rejects other OSes, and the test fixtures use unix-only APIs (os.Getuid,
// AF_UNIX sockets). Including (linux || darwin) keeps `go test -tags=integration`
// portable on Windows-builders that may run package-level vet/build.
package daemon_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/daemon/internal/verifycli"
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
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
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

// TestShutdownWithIdleClient confirms the daemon shuts down promptly even
// when a client is connected and not sending anything. A misbehaving emitter
// that connects and idles MUST NOT prevent graceful shutdown. The test's
// connection is intentionally left open across the cancel — the test's own
// defer would otherwise close it and mask the bug.
func TestShutdownWithIdleClient(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(dir, "events.sock"),
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		ChainID:              "idle",
		IssuerID:             "did:t",
		VerificationMethodID: "did:t#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	// Deliberately do NOT close conn. We're proving the daemon can shut down
	// while an idle peer is still connected.

	// Sleep long enough that the daemon's per-conn goroutine has definitely
	// entered io.ReadFull before we cancel — otherwise the goroutine would
	// observe ctx.Done() at the top of its loop and exit early, masking the
	// bug we're testing for.
	time.Sleep(100 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("daemon Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		conn.Close() // cleanup so the goroutine doesn't outlive the test
		t.Fatal("daemon did not shut down within 3s with an idle client connected (per-conn readers must observe context cancellation)")
	}
	conn.Close()
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

	// runOnce starts the daemon, emits `frames` new receipts, waits for the
	// chain to reach `expectedTotal` (so the second run cannot finish before
	// its emits are processed by polling against a stale baseline), then
	// shuts the daemon down cleanly.
	runOnce := func(t *testing.T, frames, expectedTotal int) {
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
		_ = waitForReceiptCount(t, dbPath, "resume-chain", expectedTotal, 5*time.Second)
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Logf("Run returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not shut down")
		}
	}

	runOnce(t, 3, 3)

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

	runOnce(t, 3, 6)

	receipts := waitForReceiptCount(t, dbPath, "resume-chain", 6, 5*time.Second)
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
}

// TestPublishedPublicKeyHasMode0644 confirms the daemon writes the public-key
// sibling file at the documented mode on every startup. The verify CLI relies
// on this file being world-readable so a non-daemon-user verifier (operator,
// CI runner, audit script) can load it without elevated access.
func TestPublishedPublicKeyHasMode0644(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	info, err := os.Stat(cfg.PublicKeyPath)
	if err != nil {
		t.Fatalf("daemon did not publish public key at %s: %v", cfg.PublicKeyPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("public key perm = %o, want 0644", perm)
	}
}

// TestVerifyCLIWhileDaemonRunning is the read-side counterpart to the chain-
// integrity test: with the daemon actively writing, agent-receipts verify
// must succeed using the published public-key file and the OpenReadOnly DB
// path. This is the "must not collide with the daemon's exclusive ownership
// of the write side" half of the acceptance criterion.
func TestVerifyCLIWhileDaemonRunning(t *testing.T) {
	cfg, _, _ := startDaemon(t)

	const frames = 5
	for i := 0; i < frames; i++ {
		emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
			Version:   "1",
			TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: "verify-while-running",
			Channel:   "sdk",
			Tool:      pipeline.EmitterTool{Name: "noop"},
			Decision:  "allowed",
		})
	}
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, frames, 5*time.Second)

	var stdout, stderr bytes.Buffer
	code := verifycli.Run(
		[]string{"--db", cfg.DBPath, "--public-key", cfg.PublicKeyPath, "--chain-id", cfg.ChainID},
		&stdout, &stderr,
		func(string) string { return "" },
	)
	if code != verifycli.ExitOK {
		t.Fatalf("verify exit = %d, want %d (stdout=%q stderr=%q)", code, verifycli.ExitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), fmt.Sprintf("Chain %s: VALID", cfg.ChainID)) {
		t.Errorf("stdout = %q, expected VALID line", stdout.String())
	}
}

// TestVerifyCLIWithDaemonStopped is the "Independent verifiability is not
// gated on daemon availability" acceptance criterion. Start the daemon, emit
// some receipts, shut the daemon down, then run agent-receipts verify against
// the on-disk DB and the published public key. Must succeed.
func TestVerifyCLIWithDaemonStopped(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		SocketPath:           filepath.Join(dir, "events.sock"),
		DBPath:               filepath.Join(dir, "receipts.db"),
		KeyPath:              filepath.Join(dir, "signing.key"),
		PublicKeyPath:        filepath.Join(dir, "signing.key.pub"),
		ChainID:              "stopped-chain",
		IssuerID:             "did:agent-receipts-daemon:integration",
		VerificationMethodID: "did:agent-receipts-daemon:integration#k1",
		Logger:               log.New(io.Discard, "", 0),
	}
	writeTestKey(t, cfg.KeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx, cfg) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	const frames = 3
	for i := 0; i < frames; i++ {
		emitFrame(t, cfg.SocketPath, pipeline.EmitterFrame{
			Version:   "1",
			TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: "verify-after-stop",
			Channel:   "sdk",
			Tool:      pipeline.EmitterTool{Name: "noop"},
			Decision:  "allowed",
		})
	}
	_ = waitForReceiptCount(t, cfg.DBPath, cfg.ChainID, frames, 5*time.Second)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Logf("daemon Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not shut down within 3s")
	}

	// Sanity-check the daemon really is gone before running verify; otherwise
	// a passing test wouldn't actually demonstrate the daemon-down property.
	if conn, err := net.Dial("unix", cfg.SocketPath); err == nil {
		conn.Close()
		t.Fatal("socket still accepting connections after cancel — daemon did not stop")
	}

	var stdout, stderr bytes.Buffer
	code := verifycli.Run(
		[]string{"--db", cfg.DBPath, "--public-key", cfg.PublicKeyPath, "--chain-id", cfg.ChainID},
		&stdout, &stderr,
		func(string) string { return "" },
	)
	if code != verifycli.ExitOK {
		t.Fatalf("verify with daemon stopped: exit = %d, want %d (stdout=%q stderr=%q)", code, verifycli.ExitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), fmt.Sprintf("Chain %s: VALID (%d receipts)", cfg.ChainID, frames)) {
		t.Errorf("stdout = %q, expected VALID + count line", stdout.String())
	}
}
