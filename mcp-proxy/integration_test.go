//go:build integration

package integration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

// TestAuditPipelineToolCall simulates the proxy handler's tool call pipeline:
// classify -> score -> policy -> audit. Receipt emission now goes to the daemon
// via the emitter (ADR-0010); see cmd/mcp-proxy/emitter_integration_test.go
// for end-to-end daemon receipt tests.
func TestAuditPipelineToolCall(t *testing.T) {
	auditDB, err := audit.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditDB.Close() })

	sessionID := "test-session"
	if err := auditDB.CreateSession(sessionID, "test-server", "echo"); err != nil {
		t.Fatal(err)
	}

	engine := policy.NewEngine(policy.DefaultRules())

	// --- Tool call 1: read_file (low risk, should pass) ---

	toolName := "read_file"
	args := map[string]any{"path": "/tmp/test.txt"}

	opType := audit.ClassifyOperation(toolName)
	if opType != "read" {
		t.Errorf("expected operation type 'read', got %q", opType)
	}

	riskScore, reasons := audit.ScoreRisk(toolName, args)
	if riskScore != 0 {
		t.Errorf("expected risk score 0 for read_file, got %d (reasons: %v)", riskScore, reasons)
	}

	decision := engine.Evaluate(policy.EvalContext{
		ToolName:      toolName,
		ServerName:    "test-server",
		OperationType: opType,
		RiskScore:     riskScore,
	})
	if decision.Action != "pass" {
		t.Errorf("expected policy action 'pass', got %q", decision.Action)
	}

	// Log request and response messages.
	reqMsgID, err := auditDB.LogMessage(sessionID, "client_to_server", "1", "tools/call", `{"name":"read_file"}`)
	if err != nil {
		t.Fatal(err)
	}
	respMsgID, err := auditDB.LogMessage(sessionID, "server_to_client", "1", "", `{"result":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	_, err = auditDB.InsertToolCall(audit.ToolCallRecord{
		SessionID:     sessionID,
		RequestMsgID:  reqMsgID,
		ResponseMsgID: respMsgID,
		ToolName:      toolName,
		Arguments:     `{"path":"/tmp/test.txt"}`,
		Result:        "ok",
		OperationType: opType,
		RiskScore:     riskScore,
		RiskReasons:   reasons,
		PolicyAction:  decision.Action,
		RequestedAt:   now,
		RespondedAt:   now.Add(50 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify taxonomy classification resolves correctly.
	classification := taxonomy.ClassifyToolCall(toolName, []taxonomy.TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
	})
	if classification.ActionType != "filesystem.file.read" {
		t.Errorf("expected action type 'filesystem.file.read', got %q", classification.ActionType)
	}

	// --- Tool call 2: delete_secrets (high risk, should block) ---

	toolName2 := "delete_secrets"
	args2 := map[string]any{"target": "all"}

	opType2 := audit.ClassifyOperation(toolName2)
	if opType2 != "delete" {
		t.Errorf("expected operation type 'delete', got %q", opType2)
	}

	riskScore2, reasons2 := audit.ScoreRisk(toolName2, args2)
	if riskScore2 < 70 {
		t.Errorf("expected risk score >= 70 for delete_secrets, got %d", riskScore2)
	}

	// Verify the risk reasons include expected items.
	hasDelete := false
	hasSensitive := false
	for _, r := range reasons2 {
		if strings.Contains(r, "delete") {
			hasDelete = true
		}
		if strings.Contains(r, "sensitive") {
			hasSensitive = true
		}
	}
	if !hasDelete || !hasSensitive {
		t.Errorf("expected risk reasons to include delete and sensitive, got %v", reasons2)
	}

	decision2 := engine.Evaluate(policy.EvalContext{
		ToolName:      toolName2,
		ServerName:    "test-server",
		OperationType: opType2,
		RiskScore:     riskScore2,
	})
	if decision2.Action != "block" {
		t.Errorf("expected policy action 'block' for delete_secrets, got %q", decision2.Action)
	}
}

// TestToolClassificationFallback verifies that prefix-based classification
// provides the correct action type when no taxonomy mapping exists.
// Receipts are now emitted to the daemon (ADR-0010); this test exercises
// the classification logic the proxy uses when building the emitter event.
func TestToolClassificationFallback(t *testing.T) {
	toolName := "list_issues"

	// Taxonomy has no mapping for list_issues → falls back to ClassifyOperation.
	classification := taxonomy.ClassifyToolCall(toolName, nil)
	if classification.ActionType != "unknown" {
		t.Errorf("expected 'unknown' from taxonomy for unmapped tool, got %q", classification.ActionType)
	}

	opType := audit.ClassifyOperation(toolName)
	if opType != "read" {
		t.Errorf("expected prefix fallback to 'read' for list_issues, got %q", opType)
	}
}

// TestRedactAndEncryptRoundtrip tests the full redact -> encrypt -> decrypt pipeline.
func TestRedactAndEncryptRoundtrip(t *testing.T) {
	raw := `{"username":"alice","password":"s3cret","data":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"}`

	redacted := audit.Redact(raw)

	// Password value should be redacted.
	if strings.Contains(redacted, "s3cret") {
		t.Error("password value was not redacted")
	}
	// GitHub PAT should be redacted.
	if strings.Contains(redacted, "ghp_") {
		t.Error("GitHub PAT was not redacted")
	}
	// Non-sensitive data should be preserved.
	if !strings.Contains(redacted, "alice") {
		t.Error("non-sensitive username was incorrectly redacted")
	}

	// Encrypt the redacted data.
	salt := []byte("0123456789abcdef")
	encryptor, err := audit.NewEncryptor("test-passphrase", salt)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.Encrypt(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "enc:") {
		t.Error("expected enc: prefix on encrypted data")
	}
	if encrypted == redacted {
		t.Error("encrypted should differ from redacted")
	}

	// Decrypt and verify round-trip.
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != redacted {
		t.Errorf("decrypt round-trip failed:\n  got:  %s\n  want: %s", decrypted, redacted)
	}
}

// TestPolicyWithRiskScoring exercises the combined classify + score + evaluate pipeline.
func TestPolicyWithRiskScoring(t *testing.T) {
	engine := policy.NewEngine(policy.DefaultRules())

	tests := []struct {
		tool       string
		args       map[string]any
		wantAction string
	}{
		{"read_file", nil, "pass"},
		{"delete_secrets", nil, "block"},
		{"send_message", nil, "flag"},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			opType := audit.ClassifyOperation(tt.tool)
			riskScore, _ := audit.ScoreRisk(tt.tool, tt.args)

			decision := engine.Evaluate(policy.EvalContext{
				ToolName:      tt.tool,
				ServerName:    "test-server",
				OperationType: opType,
				RiskScore:     riskScore,
			})

			if decision.Action != tt.wantAction {
				t.Errorf("tool %q: expected action %q, got %q (opType=%s, risk=%d, rule=%s)",
					tt.tool, tt.wantAction, decision.Action, opType, riskScore, decision.RuleName)
			}
		})
	}
}
