package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

// TestRunAuditSecretsDBOpenError asserts exit 2 and non-empty stderr when the
// DB path is unopenable (Fix 1: open DB inline instead of via openAuditStore).
func TestRunAuditSecretsDBOpenError(t *testing.T) {
	var stdout, stderr strings.Builder
	// /dev/null/x.db is guaranteed to be unopenable on macOS/Linux.
	code := runAuditSecrets([]string{"-db", "/dev/null/x.db"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for bad DB path, got %d; stderr=%q", code, stderr.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr for bad DB path")
	}
}

func TestRunAuditSecretsCleanDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.CreateSession("sess-1", "test-server", "test-command"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := s.LogMessage("sess-1", "client_to_server", "", "tools/list", `{"jsonrpc":"2.0","method":"tools/list"}`); err != nil {
		t.Fatalf("log message: %v", err)
	}
	s.Close()

	var stdout, stderr strings.Builder
	code := runAuditSecrets([]string{"-db", dbPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0 for clean DB, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected no output for clean DB, got %q", stdout.String())
	}
}

func TestRunAuditSecretsWithTokens(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	ghsToken := "ghs_" + strings.Repeat("b", 36)
	ghpFineToken := "github_pat_" + strings.Repeat("c", 82)
	urlToken := "ghp_" + strings.Repeat("d", 36)

	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.CreateSession("sess-2", "test-server", "test-command"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Seed a raw message containing a ghs_ token.
	if _, err := s.LogMessage("sess-2", "client_to_server", "", "tools/call", `{"secret":"`+ghsToken+`"}`); err != nil {
		t.Fatalf("log message: %v", err)
	}
	// Seed a raw message containing a URL-param token.
	if _, err := s.LogMessage("sess-2", "client_to_server", "", "tools/call", `{"url":"https://api.example.com?token=`+urlToken+`"}`); err != nil {
		t.Fatalf("log message: %v", err)
	}
	// Seed a clean message.
	if _, err := s.LogMessage("sess-2", "server_to_client", "", "", `{"result":"ok"}`); err != nil {
		t.Fatalf("log message: %v", err)
	}
	// Seed a tool_calls row with a github_pat_ (finegrained) token in arguments.
	if _, err := s.InsertToolCall(audit.ToolCallRecord{
		SessionID:     "sess-2",
		ToolName:      "create_file",
		Arguments:     `{"token":"` + ghpFineToken + `"}`,
		OperationType: "write",
		PolicyAction:  "pass",
		RequestedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("insert tool call: %v", err)
	}
	s.Close()

	var stdout, stderr strings.Builder
	code := runAuditSecrets([]string{"-db", dbPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1 for DB with tokens, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}

	out := stdout.String()
	// Must report the ghs_ hit.
	if !strings.Contains(out, "github-app-installation") {
		t.Errorf("expected github-app-installation in output, got:\n%s", out)
	}
	// Must report the github_pat_ finegrained hit.
	if !strings.Contains(out, "github-pat-finegrained") {
		t.Errorf("expected github-pat-finegrained in output, got:\n%s", out)
	}
	// Must report the URL param token hit.
	if !strings.Contains(out, "url-param-token") {
		t.Errorf("expected url-param-token in output, got:\n%s", out)
	}
	// Output must NOT contain any of the raw token values.
	for _, tok := range []string{ghsToken, ghpFineToken, urlToken} {
		if strings.Contains(out, tok) {
			t.Errorf("output should not contain raw token %q, got:\n%s", tok, out)
		}
	}
}

func TestRunAuditSecretsCustomPattern(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	yamlPath := filepath.Join(dir, "patterns.yaml")

	if err := os.WriteFile(yamlPath, []byte(`
patterns:
  - name: internal-secret
    pattern: 'INT-SECRET-[A-Z0-9]+'
`), 0600); err != nil {
		t.Fatalf("write patterns: %v", err)
	}

	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.CreateSession("sess-3", "test", "cmd"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := s.LogMessage("sess-3", "client_to_server", "", "", `{"note":"INT-SECRET-ABC123"}`); err != nil {
		t.Fatalf("log message: %v", err)
	}
	s.Close()

	var stdout, stderr strings.Builder
	code := runAuditSecrets([]string{"-db", dbPath, "-redact-patterns", yamlPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1 for custom pattern hit, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "internal-secret") {
		t.Errorf("expected internal-secret in output, got:\n%s", stdout.String())
	}
}

// TestRunAuditSecretsDecryptError asserts that a row with an invalid ciphertext
// (enc: prefix but garbage payload) is reported as a decrypt-error hit (exit 1)
// and does not abort the scan (Fix 2).
func TestRunAuditSecretsDecryptError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.CreateSession("sess-dec", "test-server", "test-command"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Seed a row with the enc: prefix but invalid base64/ciphertext.
	if _, err := s.LogMessage("sess-dec", "client_to_server", "", "tools/call", "enc:not-base64-!!!"); err != nil {
		t.Fatalf("log message: %v", err)
	}
	s.Close()

	// Set a valid-looking key so the Encryptor is initialised and Decrypt is attempted.
	t.Setenv("BEACON_ENCRYPTION_KEY", "test-passphrase-for-decrypt-error-test")

	var stdout, stderr strings.Builder
	code := runAuditSecrets([]string{"-db", dbPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1 for decrypt error, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "decrypt-error") {
		t.Errorf("expected 'decrypt-error' in stdout, got:\n%s", stdout.String())
	}
}

// TestRunAuditSecretsJSONKeyLeak asserts that a row containing a sensitive JSON
// key with a non-redacted value is reported even when no regex pattern matches
// (Fix 4).
func TestRunAuditSecretsJSONKeyLeak(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	s, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.CreateSession("sess-json", "test-server", "test-command"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// "hunter2" does not match any built-in regex pattern.
	if _, err := s.InsertToolCall(audit.ToolCallRecord{
		SessionID:     "sess-json",
		ToolName:      "do_thing",
		Arguments:     `{"password":"hunter2"}`,
		OperationType: "write",
		PolicyAction:  "pass",
		RequestedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("insert tool call: %v", err)
	}
	s.Close()

	var stdout, stderr strings.Builder
	code := runAuditSecrets([]string{"-db", dbPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1 for JSON key leak, got %d; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "json-key=password") {
		t.Errorf("expected 'json-key=password' in stdout, got:\n%s", stdout.String())
	}
}
