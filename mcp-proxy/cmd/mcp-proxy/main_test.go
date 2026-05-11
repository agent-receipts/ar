package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
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

func withHomeDirResolver(t *testing.T, resolver func() (string, error)) {
	t.Helper()
	prev := userHomeDir
	userHomeDir = resolver
	t.Cleanup(func() { userHomeDir = prev })
}

func TestDefaultDBPathUsesHomeDir(t *testing.T) {
	home := t.TempDir()
	withHomeDirResolver(t, func() (string, error) { return home, nil })

	got := defaultDBPath("audit.db")
	want := filepath.Join(home, ".agent-receipts", "audit.db")
	if got != want {
		t.Fatalf("defaultDBPath(audit.db) = %q, want %q", got, want)
	}
}

func TestDefaultDBPathFallsBackOnResolverError(t *testing.T) {
	withHomeDirResolver(t, func() (string, error) { return "", errors.New("no home") })

	if got := defaultDBPath("audit.db"); got != "audit.db" {
		t.Fatalf("expected fallback to bare filename, got %q", got)
	}
}

func TestDefaultDBPathFallsBackOnEmptyHome(t *testing.T) {
	withHomeDirResolver(t, func() (string, error) { return "", nil })

	if got := defaultDBPath("audit.db"); got != "audit.db" {
		t.Fatalf("expected fallback for empty home, got %q", got)
	}
}

func TestDefaultDBPathRejectsRelativeHome(t *testing.T) {
	withHomeDirResolver(t, func() (string, error) { return "relative/path", nil })

	if got := defaultDBPath("audit.db"); got != "audit.db" {
		t.Fatalf("expected fallback for non-absolute home, got %q", got)
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

// captureStderr redirects os.Stderr for the duration of fn and returns the
// captured output. Log package output is routed through the same pipe.
//
// fn() runs inside an IIFE with a deferred w.Close(), so the reader
// goroutine unblocks even if fn() panics or calls t.Fatal — otherwise the
// test would hang indefinitely on io.ReadAll. The write end is closed
// exactly once.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStderr := os.Stderr
	oldLog := log.Writer()
	os.Stderr = w
	log.SetOutput(w)

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	t.Cleanup(func() {
		os.Stderr = oldStderr
		log.SetOutput(oldLog)
		r.Close()
	})

	func() {
		defer w.Close()
		fn()
	}()
	return <-done
}

// TestStartupBannerDefaultNone: -http not set at all (httpExplicit=false).
// With default rules containing pause_high_risk, the banner should emit INFO
// (not WARN) with a soft hint about opt-in.
func TestStartupBannerDefaultNone(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=true (default is "none"), httpExplicit=false
	out := captureStderr(t, func() { emitStartupBanner(summary, "", true, false) })

	if strings.Contains(out, "[WARN]") {
		t.Errorf("did not expect WARN for default-off approver, got: %s", out)
	}
	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker for default-off case, got: %s", out)
	}
	if !strings.Contains(out, "approver off by default") {
		t.Errorf("expected 'approver off by default' hint, got: %s", out)
	}
	if !strings.Contains(out, "pass -http") {
		t.Errorf("expected '-http' opt-in hint, got: %s", out)
	}
	if !strings.Contains(out, "pause_high_risk") {
		t.Errorf("expected pause rule name listed, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line, got: %s", out)
	}
}

// TestStartupBannerExplicitNone: operator passed -http=none explicitly.
// The banner line and JSON companion still print; what's suppressed is the
// trailing opt-in suffix and the WARN level — the operator made an informed
// choice and doesn't need a nudge.
func TestStartupBannerExplicitNone(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=true, httpExplicit=true
	out := captureStderr(t, func() { emitStartupBanner(summary, "", true, true) })

	if strings.Contains(out, "[WARN]") {
		t.Errorf("did not expect WARN for explicit -http=none, got: %s", out)
	}
	if strings.Contains(out, "approver off by default") {
		t.Errorf("did not expect default-off hint for explicit -http=none, got: %s", out)
	}
	if !strings.Contains(out, "approver: disabled") {
		t.Errorf("expected 'approver: disabled' for explicit -http=none, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line to still print, got: %s", out)
	}
}

// TestStartupBannerExplicitAddr: operator passed -http 127.0.0.1:0 and the
// listener is up. Banner should show INFO with the resolved URL.
func TestStartupBannerExplicitAddr(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=false, httpExplicit=true, approvalURL set
	out := captureStderr(t, func() {
		emitStartupBanner(summary, "http://127.0.0.1:8081", false, true)
	})

	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker, got: %s", out)
	}
	if !strings.Contains(out, "approver: http://127.0.0.1:8081") {
		t.Errorf("expected approver URL in banner, got: %s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN when approver is set, got: %s", out)
	}
}

func TestStartupBannerNoPauseRulesNoWarn(t *testing.T) {
	// Pure-flag ruleset: no approver needed, so empty URL should not warn.
	summary := policy.NewEngine([]policy.Rule{
		{Name: "flag_all", Enabled: true, Action: "flag"},
	}).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "", false, false) })

	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN for flag-only ruleset, got: %s", out)
	}
}

// TestStartupBannerWarnsWhenApproverMissing covers the edge case where
// approverDisabled=false but approvalURL is also empty (i.e. no listener and
// no explicit opt-out). This should not happen in normal operation (the default
// is now "none" so approverDisabled will be true), but the WARN path must
// remain reachable for safety.
func TestStartupBannerWarnsWhenApproverMissing(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	// approverDisabled=false and approvalURL="" — the unusual "neither" case
	out := captureStderr(t, func() { emitStartupBanner(summary, "", false, true) })

	if !strings.Contains(out, "[WARN]") {
		t.Errorf("expected WARN marker in banner, got: %s", out)
	}
	if !strings.Contains(out, "approver: NONE") {
		t.Errorf("expected 'approver: NONE' in banner, got: %s", out)
	}
	if !strings.Contains(out, "pause rules will fail") {
		t.Errorf("expected pause-rules-will-fail hint, got: %s", out)
	}
	if !strings.Contains(out, "pause_high_risk") {
		t.Errorf("expected pause rule name listed, got: %s", out)
	}
	if !strings.Contains(out, `"event":"policy_banner"`) {
		t.Errorf("expected machine-readable companion line, got: %s", out)
	}
}

// TestStartupBannerInfoWhenApproverSet covers the normal opt-in case:
// operator passed -http 127.0.0.1:8081 and the listener is up.
func TestStartupBannerInfoWhenApproverSet(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "http://127.0.0.1:8081", false, true) })

	if !strings.Contains(out, "[INFO]") {
		t.Errorf("expected INFO marker, got: %s", out)
	}
	if !strings.Contains(out, "approver: http://127.0.0.1:8081") {
		t.Errorf("expected approver URL in banner, got: %s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN when approver is set, got: %s", out)
	}
}

// TestBindFailureDiagnostic verifies that the actionable error message on a
// busy port names the address and suggests both remediation options. It calls
// the same formatBindFailure helper main.go uses, so the test fails if the
// real output regresses (rather than asserting against a re-implemented copy).
// The os.Exit(1) is not exercised here — that's integration-level.
func TestBindFailureDiagnostic(t *testing.T) {
	// Reproduce a real bind failure so the err string in the message matches
	// what an operator would actually see.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not bind listener for test setup: %v", err)
	}
	defer ln.Close()
	busyAddr := ln.Addr().String()

	_, bindErr := net.Listen("tcp", busyAddr)
	if bindErr == nil {
		t.Skip("could not reproduce busy-port condition on this platform")
	}

	msg := formatBindFailure(busyAddr, bindErr)

	for _, want := range []string{
		busyAddr,
		bindErr.Error(),
		"Fix:",
		"-http 127.0.0.1:0",
		"-http=none",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("bind-failure message missing %q:\n%s", want, msg)
		}
	}
}

func TestApprovalRejectionResponseDistinguishesCases(t *testing.T) {
	cases := []struct {
		status   audit.ApprovalStatus
		wantCode int
		wantMsg  string
	}{
		{audit.ApprovalDenied, -32002, "denied by approval workflow"},
		{audit.ApprovalTimedOut, -32002, "timed out"},
		{audit.ApprovalNoApprover, -32003, "no approver configured"},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			code, msg := approvalRejectionResponse("create_pull_request", "pause_high_risk", 70, "abc", c.status, 15*time.Second)
			if code != c.wantCode {
				t.Errorf("code = %d, want %d", code, c.wantCode)
			}
			if !strings.Contains(msg, c.wantMsg) {
				t.Errorf("msg = %q, should contain %q", msg, c.wantMsg)
			}
		})
	}
}

func TestBuildApprovalDeniedMessageNoApprover(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc", audit.ApprovalNoApprover, 15*time.Second)
	for _, want := range []string{
		"no approver configured",
		"pause_high_risk",
		"create_pull_request",
		"-http",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in message, got %q", want, got)
		}
	}
}

func TestRecordRejectedToolCallPersists(t *testing.T) {
	db, err := audit.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	sessionID := "test-sess"
	if err := db.CreateSession(sessionID, "srv", "cmd"); err != nil {
		t.Fatalf("create session: %v", err)
	}

	recordRejectedToolCall(db, sessionID, rejectedCall{
		toolName:     "create_pull_request",
		policyAction: "rejected",
		opType:       "write",
		riskScore:    70,
		requestedAt:  time.Now(),
	})

	st, err := db.TimingStats(sessionID, 10)
	if err != nil {
		t.Fatalf("TimingStats: %v", err)
	}
	if len(st.PolicyActions) != 1 {
		t.Fatalf("expected 1 policy-action row, got %d", len(st.PolicyActions))
	}
	row := st.PolicyActions[0]
	if row.ToolName != "create_pull_request" {
		t.Errorf("tool name = %q", row.ToolName)
	}
	if row.Rejected != 1 {
		t.Errorf("expected Rejected=1, got %d", row.Rejected)
	}
}

func TestDiagnoseConfigNoApproverWithPauseRules(t *testing.T) {
	report, healthy := DiagnoseConfig("", "", func(url string) (string, error) {
		t.Fatalf("probe should not be called when URL empty")
		return "", nil
	})

	if healthy {
		t.Errorf("expected unhealthy when pause rules exist but no approver, got healthy")
	}
	if len(report.Issues) == 0 {
		t.Errorf("expected at least one issue")
	}
	if report.ApproverReach != "not_configured" {
		t.Errorf("approver reach = %q, want not_configured", report.ApproverReach)
	}
	if len(report.PauseRules) == 0 {
		t.Errorf("expected pause rules listed from defaults")
	}
}

func TestDiagnoseConfigHealthyWithReachableApprover(t *testing.T) {
	report, healthy := DiagnoseConfig("", "http://example.invalid", func(url string) (string, error) {
		return "HTTP 200", nil
	})

	if !healthy {
		t.Errorf("expected healthy when approver probe succeeds, got issues: %v", report.Issues)
	}
	if report.ApproverReach != "reachable" {
		t.Errorf("approver reach = %q, want reachable", report.ApproverReach)
	}
}

func TestDiagnoseConfigUnreachableApproverIsUnhealthy(t *testing.T) {
	report, healthy := DiagnoseConfig("", "http://example.invalid", func(url string) (string, error) {
		return "", errors.New("connection refused")
	})

	if healthy {
		t.Errorf("expected unhealthy when approver unreachable")
	}
	if report.ApproverReach != "unreachable" {
		t.Errorf("approver reach = %q, want unreachable", report.ApproverReach)
	}
}

func writeFileWithPerm(t *testing.T, dir string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("create test file: %v", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func TestCheckOpenFilePermissions0600OK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	path := writeFileWithPerm(t, t.TempDir(), 0o600)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if got := checkOpenFilePermissions(f); got != "" {
		t.Errorf("expected no warning for 0600, got %q", got)
	}
}

func TestCheckOpenFilePermissions0400OK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	path := writeFileWithPerm(t, t.TempDir(), 0o400)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if got := checkOpenFilePermissions(f); got != "" {
		t.Errorf("expected no warning for 0400, got %q", got)
	}
}

func TestCheckOpenFilePermissions0644Warns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	path := writeFileWithPerm(t, t.TempDir(), 0o644)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	got := checkOpenFilePermissions(f)
	if got == "" {
		t.Fatalf("expected warning for 0644, got empty string")
	}
	if !strings.Contains(got, path) {
		t.Errorf("warning should contain path, got %q", got)
	}
	if !strings.Contains(got, "chmod 600") {
		t.Errorf("warning should mention chmod 600, got %q", got)
	}
}

func TestCheckOpenFilePermissions0666Warns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	path := writeFileWithPerm(t, t.TempDir(), 0o666)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if got := checkOpenFilePermissions(f); got == "" {
		t.Errorf("expected warning for 0666, got empty string")
	}
}

// ---------------------------------------------------------------------------
// resolveVersion
// ---------------------------------------------------------------------------

func TestResolveVersionFallback(t *testing.T) {
	// version is the package-level var set by ldflags. Save and restore it.
	orig := version
	version = ""
	t.Cleanup(func() { version = orig })

	// When no ldflags version is set and this runs under `go test` (devel),
	// resolveVersion must return a non-empty string — either the module
	// version or "dev".
	got := resolveVersion()
	if got == "" {
		t.Error("resolveVersion() returned empty string")
	}
}

func TestResolveVersionLDFlags(t *testing.T) {
	orig := version
	version = "v1.2.3"
	t.Cleanup(func() { version = orig })

	if got := resolveVersion(); got != "v1.2.3" {
		t.Errorf("resolveVersion() = %q, want %q", got, "v1.2.3")
	}
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------

func TestGenerateTokenLength(t *testing.T) {
	tok := generateToken(16)
	// 16 bytes → 32 hex chars.
	if len(tok) != 32 {
		t.Errorf("generateToken(16) len = %d, want 32", len(tok))
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	a, b := generateToken(16), generateToken(16)
	if a == b {
		t.Errorf("generateToken produced identical tokens: %s", a)
	}
}

func TestGenerateTokenHexCharset(t *testing.T) {
	tok := generateToken(32)
	for _, c := range tok {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("generateToken returned non-hex character %q in %q", c, tok)
		}
	}
}

// ---------------------------------------------------------------------------
// emitPolicyEvent
// ---------------------------------------------------------------------------

func TestEmitPolicyEventLogsStructuredLine(t *testing.T) {
	out := captureStderr(t, func() {
		emitPolicyEvent("create_pr", "pause_high_risk", 75, "pause", "http://127.0.0.1:7778", "approved", 120)
	})

	for _, want := range []string{
		`tool="create_pr"`,
		`rule="pause_high_risk"`,
		`risk=75`,
		`action="pause"`,
		`approver="http://127.0.0.1:7778"`,
		`outcome="approved"`,
		`duration_ms=120`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("emitPolicyEvent output missing %q:\n%s", want, out)
		}
	}
}

func TestEmitPolicyEventNoApproverShowsNONE(t *testing.T) {
	out := captureStderr(t, func() {
		emitPolicyEvent("delete_file", "block_deletes", 90, "block", "", "blocked", 0)
	})
	if !strings.Contains(out, `approver="NONE"`) {
		t.Errorf("expected approver=NONE when URL is empty, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// buildApprovalDeniedMessage — default (unknown status) branch
// ---------------------------------------------------------------------------

func TestBuildApprovalDeniedMessageDefaultBranch(t *testing.T) {
	// Use an ApprovalStatus value that doesn't match Denied, TimedOut or NoApprover.
	got := buildApprovalDeniedMessage("tool", "rule", 50, "id", audit.ApprovalStatus("unknown"), time.Second)
	if !strings.Contains(got, "denied by approval workflow") {
		t.Errorf("default branch should contain 'denied by approval workflow', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// startHTTPServer approval handler
// ---------------------------------------------------------------------------

// newApprovalTestServer starts an in-process HTTP server using startHTTPServer
// and returns the server URL and the approval manager.
func newApprovalTestServer(t *testing.T) (string, *audit.ApprovalManager, string) {
	t.Helper()
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go startHTTPServer(ln, approvals, token)
	return "http://" + ln.Addr().String(), approvals, token
}

func TestStartHTTPServerApproveFlow(t *testing.T) {
	baseURL, approvals, token := newApprovalTestServer(t)
	approvalID := generateToken(8)

	// Start a waiter that will receive the approval.
	result := make(chan audit.ApprovalStatus, 1)
	go func() {
		result <- approvals.WaitForApproval(approvalID, 3*time.Second)
	}()

	// Send the POST /approve request.
	url := fmt.Sprintf("%s/api/tool-calls/%s/approve", baseURL, approvalID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST approve: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("approve: status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "approved" {
		t.Errorf("approve response body = %v, want status=approved", body)
	}

	select {
	case status := <-result:
		if status != audit.ApprovalApproved {
			t.Errorf("WaitForApproval = %s, want approved", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for approval status")
	}
}

func TestStartHTTPServerDenyFlow(t *testing.T) {
	baseURL, approvals, token := newApprovalTestServer(t)
	approvalID := generateToken(8)

	result := make(chan audit.ApprovalStatus, 1)
	go func() {
		result <- approvals.WaitForApproval(approvalID, 3*time.Second)
	}()

	url := fmt.Sprintf("%s/api/tool-calls/%s/deny", baseURL, approvalID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST deny: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("deny: status = %d, want 200", resp.StatusCode)
	}

	select {
	case status := <-result:
		if status != audit.ApprovalDenied {
			t.Errorf("WaitForApproval = %s, want denied", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for denial status")
	}
}

func TestStartHTTPServerUnauthorized(t *testing.T) {
	baseURL, _, token := newApprovalTestServer(t)

	url := fmt.Sprintf("%s/api/tool-calls/someid/approve", baseURL)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer wrong-"+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", resp.StatusCode)
	}
}

func TestStartHTTPServerInvalidPath(t *testing.T) {
	baseURL, _, token := newApprovalTestServer(t)

	url := fmt.Sprintf("%s/api/tool-calls/approve", baseURL) // missing action segment
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short path: status = %d, want 400", resp.StatusCode)
	}
}

func TestStartHTTPServerNotFound(t *testing.T) {
	baseURL, _, token := newApprovalTestServer(t)

	// No pending approval with this ID, so Approve returns false.
	url := fmt.Sprintf("%s/api/tool-calls/nonexistent-id/approve", baseURL)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no pending: status = %d, want 404", resp.StatusCode)
	}
}

func TestStartHTTPServerUnknownAction(t *testing.T) {
	baseURL, _, token := newApprovalTestServer(t)

	url := fmt.Sprintf("%s/api/tool-calls/someid/unknown-action", baseURL)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown action: status = %d, want 404", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// DiagnoseConfig with rules file
// ---------------------------------------------------------------------------

func TestDiagnoseConfigWithRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesPath := dir + "/rules.yaml"
	if err := os.WriteFile(rulesPath, []byte(`rules:
  - name: flag_all
    enabled: true
    action: flag
`), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	report, healthy := DiagnoseConfig(rulesPath, "", func(url string) (string, error) {
		return "", nil
	})

	// flag_all has no pause rules, so no approver issues.
	if !healthy {
		t.Errorf("expected healthy for flag-only ruleset, got issues: %v", report.Issues)
	}
	if report.RulesPath != rulesPath {
		t.Errorf("RulesPath = %q, want %q", report.RulesPath, rulesPath)
	}
	if len(report.FlagRules) == 0 {
		t.Errorf("expected at least one flag rule in FlagRules")
	}
}

func TestDiagnoseConfigBadRulesFile(t *testing.T) {
	report, healthy := DiagnoseConfig("/nonexistent/rules.yaml", "", func(url string) (string, error) {
		return "", nil
	})
	if healthy {
		t.Errorf("expected unhealthy for missing rules file")
	}
	if len(report.Issues) == 0 {
		t.Errorf("expected issues for bad rules file")
	}
}

// ---------------------------------------------------------------------------
// recordRejectedToolCall with approvalWaitUs
// ---------------------------------------------------------------------------

func TestRecordRejectedToolCallWithApprovalWait(t *testing.T) {
	db, err := audit.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	sessionID := "sess-approval-wait"
	if err := db.CreateSession(sessionID, "srv", "cmd"); err != nil {
		t.Fatalf("create session: %v", err)
	}

	recordRejectedToolCall(db, sessionID, rejectedCall{
		toolName:       "push_to_prod",
		policyAction:   "rejected",
		opType:         "execute",
		riskScore:      80,
		requestedAt:    time.Now(),
		approvalWaitUs: 5000000, // 5 seconds
	})

	st, err := db.TimingStats(sessionID, 10)
	if err != nil {
		t.Fatalf("TimingStats: %v", err)
	}
	if len(st.PolicyActions) != 1 {
		t.Fatalf("expected 1 policy-action row, got %d", len(st.PolicyActions))
	}
	if st.PolicyActions[0].ToolName != "push_to_prod" {
		t.Errorf("tool name = %q", st.PolicyActions[0].ToolName)
	}
}

// ---------------------------------------------------------------------------
// runFollowLoop — JSON output path
// ---------------------------------------------------------------------------

func TestRunFollowLoopJSONOutput(t *testing.T) {
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
		done <- runFollowLoop(ctx, s, startRowID, store.Query{}, 10*time.Millisecond, true, w)
	}()

	storeFollowReceipt(t, s, kp, 1, "chain-json-follow", nil)

	// Wait for the JSON line to appear.
	deadline := time.Now().Add(3 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out = w.waitForWrite(t, 3*time.Second)
		if strings.Contains(out, "chain-json-follow") {
			break
		}
	}
	if !strings.Contains(out, "chain-json-follow") {
		t.Fatalf("JSON follow output missing chain ID: %q", out)
	}
	// Must be valid NDJSON.
	line := strings.TrimSpace(strings.Split(out, "\n")[0])
	var parsed map[string]any
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		t.Errorf("follow JSON output is not valid JSON: %v\nline: %q", err, line)
	}
	cancel()
	<-done
}

// ---------------------------------------------------------------------------
// httptest-based handler unit test (tests mux without a real listener)
// ---------------------------------------------------------------------------

func TestApprovalHTTPHandlerDirectly(t *testing.T) {
	token := "test-token-direct"
	approvals := audit.NewApprovalManager()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tool-calls/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		id := parts[3]
		action := parts[4]
		switch {
		case r.Method == "POST" && action == "approve":
			if approvals.Approve(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"approved"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		case r.Method == "POST" && action == "deny":
			if approvals.Deny(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"denied"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	// GET method (unsupported) should return 404.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tool-calls/id/approve", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET approve: status = %d, want 404", rec.Code)
	}

	// No token → 401.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/tool-calls/id/approve", nil)
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// ensureDir (non-ensureDBDir variant)
// ---------------------------------------------------------------------------

func TestEnsureDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "file.txt")
	if err := ensureDir(target); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "a", "b"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("ensureDir did not create directory")
	}
}

func TestEnsureDirBareFilename(t *testing.T) {
	// dir component is "." — should be a no-op.
	if err := ensureDir("file.db"); err != nil {
		t.Fatalf("ensureDir for bare filename should be no-op: %v", err)
	}
}
