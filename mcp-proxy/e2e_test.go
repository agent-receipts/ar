//go:build e2e

package e2e_test

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	receiptStore "github.com/agent-receipts/ar/sdk/go/store"
)

// buildBinary compiles a Go package into the given directory and returns the binary path.
func buildBinary(t *testing.T, pkg, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build %s: %v", pkg, err)
	}
	return out
}

// sendJSON marshals msg to JSON and writes it as a newline-delimited message.
func sendJSON(t *testing.T, w io.Writer, msg any) {
	t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readResponse reads one JSON-RPC response line and returns it parsed.
func readResponse(t *testing.T, scanner *bufio.Scanner) map[string]any {
	t.Helper()
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			t.Fatalf("scan: %v", err)
		}
		t.Fatal("unexpected EOF from proxy")
	}
	var resp map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", scanner.Text(), err)
	}
	return resp
}

// waitForExit closes stdin to signal EOF and waits for the proxy process to
// exit. This ensures the proxy has released all database locks before the test
// opens the database.
func waitForExit(t *testing.T, stdin io.WriteCloser, cmd *exec.Cmd) {
	t.Helper()
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Logf("proxy exited with: %v (may be expected)", err)
	}
}

// startProxy builds and starts the proxy with a mock MCP server, returning
// the stdin writer, stdout scanner, command, and keypair.
func startProxy(t *testing.T, chainID string) (io.WriteCloser, *bufio.Scanner, *exec.Cmd, receipt.KeyPair, string) {
	t.Helper()
	tmpDir := t.TempDir()

	mockBin := buildBinary(t, "./testdata", tmpDir, "mock-server")
	proxyBin := buildBinary(t, "./cmd/mcp-proxy", tmpDir, "mcp-proxy")

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyPath, []byte(kp.PrivateKey), 0600); err != nil {
		t.Fatal(err)
	}

	auditDBPath := filepath.Join(tmpDir, "audit.db")
	receiptDBPath := filepath.Join(tmpDir, "receipts.db")

	cmd := exec.Command(proxyBin,
		"--db", auditDBPath,
		"--receipt-db", receiptDBPath,
		"--key", keyPath,
		"--chain", chainID,
		"--http", "127.0.0.1:0",
		"--", mockBin,
	)
	cmd.Stderr = os.Stderr

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		stdinPipe.Close()
		cmd.Wait() //nolint: may return error on second call, that's fine
	})

	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// Wait for the proxy to start the child process.
	time.Sleep(500 * time.Millisecond)

	return stdinPipe, scanner, cmd, kp, receiptDBPath
}

func TestE2EProxyToolCallFlow(t *testing.T) {
	chainID := "e2e-test-chain"
	stdin, scanner, cmd, kp, receiptDBPath := startProxy(t, chainID)

	// Send tools/call for read_file.
	sendJSON(t, stdin, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": "read_file", "arguments": map[string]any{"path": "/tmp/test"}},
	})

	resp1 := readResponse(t, scanner)
	if resp1["error"] != nil {
		t.Fatalf("expected success for read_file, got error: %v", resp1["error"])
	}

	// Send tools/call for write_file.
	sendJSON(t, stdin, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params":  map[string]any{"name": "write_file", "arguments": map[string]any{"path": "/tmp/out", "content": "hello"}},
	})

	resp2 := readResponse(t, scanner)
	if resp2["error"] != nil {
		t.Fatalf("expected success for write_file, got error: %v", resp2["error"])
	}

	// Close stdin to signal EOF and wait for the proxy to exit so it
	// releases all database locks before we open the receipt store.
	waitForExit(t, stdin, cmd)

	// Open the receipt store and verify the chain.
	rStore, err := receiptStore.Open(receiptDBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rStore.Close()

	chain, err := rStore.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(chain))
	}

	// Verify chain integrity.
	result := receipt.VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain verification failed: broken at %d, error: %s", result.BrokenAt, result.Error)
	}

	// Verify sequence numbers.
	if chain[0].CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("receipt 0: expected sequence 1, got %d", chain[0].CredentialSubject.Chain.Sequence)
	}
	if chain[1].CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("receipt 1: expected sequence 2, got %d", chain[1].CredentialSubject.Chain.Sequence)
	}

	// First receipt should have no previous hash.
	if chain[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Error("receipt 0: expected nil PreviousReceiptHash")
	}
	// Second receipt should have a previous hash.
	if chain[1].CredentialSubject.Chain.PreviousReceiptHash == nil {
		t.Error("receipt 1: expected non-nil PreviousReceiptHash")
	}
}

func TestE2EProxyBlockedCall(t *testing.T) {
	chainID := "e2e-test-blocked"
	stdin, scanner, cmd, _, receiptDBPath := startProxy(t, chainID)

	// Send a tool call that should be blocked: delete_secrets has risk >= 70.
	sendJSON(t, stdin, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": "delete_secrets", "arguments": map[string]any{}},
	})

	resp := readResponse(t, scanner)

	// Should be a JSON-RPC error.
	errObj, ok := resp["error"]
	if !ok || errObj == nil {
		t.Fatalf("expected error response for blocked call, got: %v", resp)
	}
	errMap, ok := errObj.(map[string]any)
	if !ok {
		t.Fatalf("expected error to be an object, got: %T", errObj)
	}
	code, _ := errMap["code"].(float64)
	if int(code) != -32001 {
		t.Errorf("expected error code -32001, got %v", errMap["code"])
	}

	// Close stdin and wait for the proxy to exit so it releases all
	// database locks before we open the receipt store.
	waitForExit(t, stdin, cmd)

	// Verify no receipts were created for the blocked call.
	rStore, err := receiptStore.Open(receiptDBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rStore.Close()

	chain, err := rStore.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 0 {
		t.Errorf("expected 0 receipts for blocked call, got %d", len(chain))
	}
}
