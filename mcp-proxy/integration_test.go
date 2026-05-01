//go:build integration

package integration_test

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	receiptStore "github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

// TestAuditPipelineToolCall simulates the proxy handler's tool call pipeline:
// classify -> score -> policy -> audit -> receipt emission.
func TestAuditPipelineToolCall(t *testing.T) {
	auditDB, err := audit.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditDB.Close() })

	rStore, err := receiptStore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rStore.Close() })

	sessionID := "test-session"
	if err := auditDB.CreateSession(sessionID, "test-server", "echo"); err != nil {
		t.Fatal(err)
	}

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	engine := policy.NewEngine(policy.DefaultRules())
	chainID := "test-chain-pipeline"
	issuerDID := "did:agent:test"
	principalDID := "did:user:test"
	sequence := 0
	var prevHash *string

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

	// Emit receipt for the passed tool call.
	classification := taxonomy.ClassifyToolCall(toolName, []taxonomy.TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
	})

	canonical, err := receipt.Canonicalize(args)
	if err != nil {
		t.Fatalf("canonicalize args: %v", err)
	}
	argsHash := receipt.SHA256Hash(canonical)

	sequence++
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: issuerDID},
		Principal: receipt.Principal{ID: principalDID},
		Action: receipt.Action{
			Type:           classification.ActionType,
			RiskLevel:      classification.RiskLevel,
			ParametersHash: argsHash,
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence:            sequence,
			PreviousReceiptHash: prevHash,
			ChainID:             chainID,
		},
	})

	signed, err := receipt.Sign(unsigned, kp.PrivateKey, issuerDID+"#key-1")
	if err != nil {
		t.Fatal(err)
	}
	h, err := receipt.HashReceipt(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := rStore.Insert(signed, h); err != nil {
		t.Fatal(err)
	}
	prevHash = &h

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

	// Blocked calls do NOT generate receipts.

	// --- Verify final state ---

	chain, err := rStore.GetChain(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 receipt (blocked call should not produce one), got %d", len(chain))
	}

	result := receipt.VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("chain verification failed: broken at %d", result.BrokenAt)
	}
}

// TestToolNameInReceipt verifies that the tool name is stored in the receipt
// and that prefix-based classification provides the correct action type
// when no taxonomy mapping exists (fixes #109).
func TestToolNameInReceipt(t *testing.T) {
	rStore, err := receiptStore.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rStore.Close() })

	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	toolName := "list_issues"
	args := map[string]any{"repo": "agent-receipts/ar"}

	// Taxonomy has no mapping for list_issues → falls back to ClassifyOperation.
	classification := taxonomy.ClassifyToolCall(toolName, nil)
	actionType := classification.ActionType
	riskLevel := classification.RiskLevel
	if actionType == "unknown" {
		actionType = audit.ClassifyOperation(toolName)
		switch actionType {
		case "read":
			riskLevel = receipt.RiskLow
		case "write":
			riskLevel = receipt.RiskMedium
		case "delete":
			riskLevel = receipt.RiskHigh
		case "execute":
			riskLevel = receipt.RiskHigh
		}
	}

	canonical, err := receipt.Canonicalize(args)
	if err != nil {
		t.Fatalf("canonicalize args: %v", err)
	}
	argsHash := receipt.SHA256Hash(canonical)

	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action: receipt.Action{
			Type:           actionType,
			ToolName:       toolName,
			RiskLevel:      riskLevel,
			ParametersHash: argsHash,
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:   receipt.Chain{Sequence: 1, ChainID: "test-chain-toolname"},
	})

	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	h, err := receipt.HashReceipt(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := rStore.Insert(signed, h); err != nil {
		t.Fatal(err)
	}

	// Retrieve and verify the receipt.
	got, err := rStore.GetByID(signed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected receipt, got nil")
	}
	if got.CredentialSubject.Action.ToolName != "list_issues" {
		t.Errorf("expected action.tool_name %q, got %q", "list_issues", got.CredentialSubject.Action.ToolName)
	}
	if got.CredentialSubject.Action.Type != "read" {
		t.Errorf("expected action.type %q, got %q", "read", got.CredentialSubject.Action.Type)
	}
	if got.CredentialSubject.Action.RiskLevel != receipt.RiskLow {
		t.Errorf("expected action.risk_level %q, got %q", receipt.RiskLow, got.CredentialSubject.Action.RiskLevel)
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
