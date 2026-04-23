package main

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
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
	t.Cleanup(func() {
		os.Stderr = oldStderr
		log.SetOutput(oldLog)
	})

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	w.Close()
	return <-done
}

func TestStartupBannerWarnsWhenApproverMissing(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "") })

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

func TestStartupBannerInfoWhenApproverSet(t *testing.T) {
	summary := policy.NewEngine(policy.DefaultRules()).Describe()
	out := captureStderr(t, func() { emitStartupBanner(summary, "http://127.0.0.1:8081") })

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
	out := captureStderr(t, func() { emitStartupBanner(summary, "") })

	if strings.Contains(out, "WARN") {
		t.Errorf("did not expect WARN for flag-only ruleset, got: %s", out)
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
