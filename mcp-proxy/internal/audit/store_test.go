package audit

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestCreateAndEndSession(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessionID := "sess-roundtrip"
	if err := store.CreateSession(sessionID, "test-server", "test-cmd"); err != nil {
		t.Fatal(err)
	}

	if err := store.EndSession(sessionID); err != nil {
		t.Fatal(err)
	}

	// Verify ended_at is populated.
	var endedAt *string
	err = store.db.QueryRow("SELECT ended_at FROM sessions WHERE id = ?", sessionID).Scan(&endedAt)
	if err != nil {
		t.Fatal(err)
	}
	if endedAt == nil {
		t.Error("expected ended_at to be non-nil after EndSession")
	}
}

func TestLogMessageReturnsValidID(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessionID := "sess-logmsg"
	if err := store.CreateSession(sessionID, "test-server", "test-cmd"); err != nil {
		t.Fatal(err)
	}

	msgID, err := store.LogMessage(sessionID, "client_to_server", "1", "tools/call", `{"test":"data"}`)
	if err != nil {
		t.Fatal(err)
	}
	if msgID <= 0 {
		t.Errorf("expected positive message ID, got %d", msgID)
	}
}

func TestInsertToolCallAllFields(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessionID := "sess-toolcall"
	if err := store.CreateSession(sessionID, "test-server", "test-cmd"); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	policyEvalUs := int64(150)
	approvalWaitUs := int64(5000000)
	upstreamUs := int64(847000)
	tcID, err := store.InsertToolCall(ToolCallRecord{
		SessionID:      sessionID,
		RequestMsgID:   1,
		ResponseMsgID:  2,
		ToolName:       "read_file",
		Arguments:      `{"path":"/tmp/test"}`,
		Result:         `{"content":"hello"}`,
		Error:          "",
		OperationType:  "read",
		RiskScore:      10,
		RiskReasons:    []string{"file_access"},
		PolicyAction:   "pass",
		ApprovedBy:     "http",
		RequestedAt:    now,
		RespondedAt:    now.Add(100 * time.Millisecond),
		PolicyEvalUs:   &policyEvalUs,
		ApprovalWaitUs: &approvalWaitUs,
		UpstreamUs:     &upstreamUs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tcID <= 0 {
		t.Errorf("expected positive tool call ID, got %d", tcID)
	}

	// Verify approved_by was stored.
	var approvedBy *string
	err = store.db.QueryRow("SELECT approved_by FROM tool_calls WHERE id = ?", tcID).Scan(&approvedBy)
	if err != nil {
		t.Fatal(err)
	}
	if approvedBy == nil || *approvedBy != "http" {
		t.Errorf("expected approved_by = 'http', got %v", approvedBy)
	}

	// Verify phase timing columns were stored.
	var gotPolicyEval, gotApprovalWait, gotUpstream *int64
	err = store.db.QueryRow(
		"SELECT policy_eval_us, approval_wait_us, upstream_us FROM tool_calls WHERE id = ?", tcID,
	).Scan(&gotPolicyEval, &gotApprovalWait, &gotUpstream)
	if err != nil {
		t.Fatal(err)
	}
	if gotPolicyEval == nil || *gotPolicyEval != 150 {
		t.Errorf("policy_eval_us: want 150, got %v", gotPolicyEval)
	}
	if gotApprovalWait == nil || *gotApprovalWait != 5000000 {
		t.Errorf("approval_wait_us: want 5000000, got %v", gotApprovalWait)
	}
	if gotUpstream == nil || *gotUpstream != 847000 {
		t.Errorf("upstream_us: want 847000, got %v", gotUpstream)
	}
}

func TestUpdateReceiptSignUs(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessionID := "sess-receipt-timing"
	if err := store.CreateSession(sessionID, "test-server", "test-cmd"); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tcID, err := store.InsertToolCall(ToolCallRecord{
		SessionID:     sessionID,
		RequestMsgID:  1,
		ResponseMsgID: 2,
		ToolName:      "write_file",
		OperationType: "write",
		PolicyAction:  "pass",
		RequestedAt:   now,
		RespondedAt:   now.Add(50 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateReceiptSignUs(tcID, 1200); err != nil {
		t.Fatal(err)
	}

	var got *int64
	err = store.db.QueryRow("SELECT receipt_sign_us FROM tool_calls WHERE id = ?", tcID).Scan(&got)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != 1200 {
		t.Errorf("receipt_sign_us: want 1200, got %v", got)
	}
}

func TestEncryptionSalt(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// First call generates a 16-byte salt.
	salt1, err := store.EncryptionSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(salt1) != 16 {
		t.Fatalf("expected 16-byte salt, got %d", len(salt1))
	}

	// Second call returns the same salt.
	salt2, err := store.EncryptionSalt()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(salt1, salt2) {
		t.Errorf("expected same salt on second call, got %x vs %x", salt1, salt2)
	}

	// Salt is persisted in the metadata table.
	var encoded string
	err = store.db.QueryRow("SELECT value FROM metadata WHERE key = 'encryption_salt'").Scan(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(salt1, persisted) {
		t.Errorf("persisted salt doesn't match: %x vs %x", salt1, persisted)
	}
}

func TestEncryptionSaltRejectsCorrupted(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Insert a corrupted salt (wrong length).
	if _, err := store.db.Exec("INSERT INTO metadata (key, value) VALUES ('encryption_salt', 'abcd')"); err != nil {
		t.Fatal(err)
	}

	_, err = store.EncryptionSalt()
	if err == nil {
		t.Error("expected error for corrupted salt")
	}
}

func TestTimingStats(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sessionID := "sess-timing"
	if err := store.CreateSession(sessionID, "test-server", "test-cmd"); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	// Insert tool calls with known timing values.
	calls := []struct {
		tool       string
		upstream   int64
		policy     int64
		receipt    int64
		durationMs int
	}{
		{"read_file", 800000, 100, 1000, 801},
		{"read_file", 900000, 200, 1200, 901},
		{"write_file", 1200000, 150, 1500, 1202},
	}

	for i, c := range calls {
		upUs := c.upstream
		polUs := c.policy
		tcID, err := store.InsertToolCall(ToolCallRecord{
			SessionID:     sessionID,
			RequestMsgID:  int64(i*2 + 1),
			ResponseMsgID: int64(i*2 + 2),
			ToolName:      c.tool,
			OperationType: "read",
			PolicyAction:  "pass",
			RequestedAt:   now,
			RespondedAt:   now.Add(time.Duration(c.durationMs) * time.Millisecond),
			PolicyEvalUs:  &polUs,
			UpstreamUs:    &upUs,
		})
		if err != nil {
			t.Fatal(err)
		}
		recUs := c.receipt
		if err := store.UpdateReceiptSignUs(tcID, recUs); err != nil {
			t.Fatal(err)
		}
	}

	// Query all sessions.
	st, err := store.TimingStats("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 3 {
		t.Errorf("total: want 3, got %d", st.Total)
	}
	if len(st.ByTool) != 2 {
		t.Fatalf("by_tool: want 2 tools, got %d", len(st.ByTool))
	}
	// read_file has 2 calls, should be first (ordered by count desc).
	if st.ByTool[0].ToolName != "read_file" {
		t.Errorf("first tool: want read_file, got %s", st.ByTool[0].ToolName)
	}
	if st.ByTool[0].Count != 2 {
		t.Errorf("read_file count: want 2, got %d", st.ByTool[0].Count)
	}
	// AVG upstream for read_file: (800000+900000)/2 = 850000
	if st.ByTool[0].AvgUpstreamUs == nil || *st.ByTool[0].AvgUpstreamUs != 850000 {
		t.Errorf("read_file avg upstream: want 850000, got %v", st.ByTool[0].AvgUpstreamUs)
	}

	// Percentiles should exist.
	if _, ok := st.Percentiles["upstream"]; !ok {
		t.Error("missing upstream percentiles")
	}
	if _, ok := st.Percentiles["policy_eval"]; !ok {
		t.Error("missing policy_eval percentiles")
	}
	if _, ok := st.Percentiles["duration_ms"]; !ok {
		t.Error("missing duration_ms percentiles")
	}

	// Session filter: query with non-existent session.
	st2, err := store.TimingStats("nonexistent", 0)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Total != 0 {
		t.Errorf("filtered total: want 0, got %d", st2.Total)
	}

	// Session filter: query with correct session.
	st3, err := store.TimingStats(sessionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st3.Total != 3 {
		t.Errorf("session total: want 3, got %d", st3.Total)
	}
}
