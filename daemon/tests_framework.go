//go:build integration && (linux || darwin)

// Framework for Phase 1 integration tests exercising the daemon with
// multi-SDK emitters. Provides daemon startup fixtures, receipt polling,
// and concurrent emitter orchestration.
package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/daemon/internal/sockettest"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// DaemonFixture holds a running daemon instance and its configuration.
type DaemonFixture struct {
	Config    Config
	PublicKey string // PEM-encoded public key
	cancel    func()
	done      chan error
	traceBuf  *bytes.Buffer
}

// StartDaemon starts a test daemon and returns a fixture with cleanup.
// The fixture will be cleaned up automatically via t.Cleanup.
func StartDaemon(t *testing.T) *DaemonFixture {
	t.Helper()

	sockDir := sockettest.ShortSocketDir(t)
	dataDir := t.TempDir()

	cfg := Config{
		SocketPath:           filepath.Join(sockDir, "events.sock"),
		DBPath:               filepath.Join(dataDir, "receipts.db"),
		KeyPath:              filepath.Join(dataDir, "signing.key"),
		PublicKeyPath:        filepath.Join(dataDir, "signing.key.pub"),
		ChainID:              "test-chain",
		IssuerID:             "did:agent-receipts-daemon:test",
		VerificationMethodID: "did:agent-receipts-daemon:test#k1",
		Logger:               log.New(io.Discard, "", 0),
	}

	// Generate test key
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(cfg.KeyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Set up trace log for debugging
	traceBuf := &bytes.Buffer{}
	cfg.TraceLog = traceBuf

	// Start daemon
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	// Wait for socket
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon socket %s did not appear within 2s", cfg.SocketPath)
		}
		time.Sleep(10 * time.Millisecond)
	}

	fix := &DaemonFixture{
		Config:    cfg,
		PublicKey: pubPEM,
		cancel:    cancel,
		done:      done,
		traceBuf:  traceBuf,
	}

	// Cleanup on test end
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

	return fix
}

// EmitGoFrame emits a frame using the Go SDK's direct socket connection.
func (f *DaemonFixture) EmitGoFrame(t *testing.T, sessionID, channel string, tool pipeline.EmitterTool, decision string) {
	t.Helper()
	conn, err := net.Dial("unix", f.Config.SocketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", f.Config.SocketPath, err)
	}
	defer conn.Close()

	body, err := json.Marshal(pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: sessionID,
		Channel:   channel,
		Tool:      tool,
		Decision:  decision,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := socket.WriteFrame(conn, body); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	// Sync with daemon to ensure frame is fully processed
	syncWithDaemon(conn)
}

// EmitTSFrame spawns a Node.js subprocess to emit a frame via the TS SDK.
func (f *DaemonFixture) EmitTSFrame(t *testing.T, sessionID, channel string, toolName string, decision string) {
	t.Helper()

	helperPath := findHelperScript(t, "emit_ts.mjs")
	repoRoot := findSDKRoot(t)

	cmd := exec.Command("node", helperPath, f.Config.SocketPath, sessionID, channel, toolName, decision)
	cmd.Env = append(os.Environ())
	cmd.Dir = repoRoot

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("TS emitter output:\n%s", out)
		// TS frame failure is expected to be caught by the test assertion
		return
	}
}

// EmitPythonFrame spawns a Python subprocess to emit a frame via the Python SDK.
// Uses uv run to manage dependencies in the sdk/py directory.
func (f *DaemonFixture) EmitPythonFrame(t *testing.T, sessionID, channel string, toolName string, decision string) {
	t.Helper()

	helperPath := findHelperScript(t, "emit_py.py")
	repoRoot := findSDKRoot(t)

	// Use uv run from the sdk/py directory (where pyproject.toml is)
	cmd := exec.Command("uv", "run", "--", "python", helperPath, f.Config.SocketPath, sessionID, channel, toolName, decision)
	cmd.Dir = filepath.Join(repoRoot, "sdk", "py")
	cmd.Env = append(os.Environ())

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Python emitter output:\n%s", out)
		// Python frame failure is expected to be caught by the test assertion
		return
	}
}

// WaitForReceiptCount polls the store until at least `count` receipts exist
// or the timeout is exceeded.
func (f *DaemonFixture) WaitForReceiptCount(t *testing.T, count int, timeout time.Duration) []receipt.AgentReceipt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		s, err := store.Open(f.Config.DBPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		got, err := s.GetChain(f.Config.ChainID)
		s.Close()

		if err == nil && len(got) >= count {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d receipts in chain %s; got %d (err=%v)",
				count, f.Config.ChainID, len(got), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Trace returns the daemon's trace log output for debugging test failures.
func (f *DaemonFixture) Trace() string {
	return f.traceBuf.String()
}

// syncWithDaemon half-closes the write side of conn and reads until the daemon
// closes its end. This guarantees the daemon has finished processing the frame.
// Without this sync, rapid connect→write→close races the daemon's accept-loop
// processing, especially on macOS.
func syncWithDaemon(conn net.Conn) {
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

// findSDKRoot locates the repo root by finding the daemon package's parent.
// Used to construct SDK paths for subprocess emitters.
func findSDKRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the current test file directory to find go.work or agent-receipts root
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "sdk")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.work or sdk/ not found)")
		}
		dir = parent
	}
}

// findHelperScript locates a test helper script in daemon/helpers/.
func findHelperScript(t *testing.T, name string) string {
	t.Helper()
	root := findSDKRoot(t)
	helperPath := filepath.Join(root, "daemon", "helpers", name)
	if _, err := os.Stat(helperPath); err != nil {
		t.Fatalf("helper script not found: %s", helperPath)
	}
	return helperPath
}
