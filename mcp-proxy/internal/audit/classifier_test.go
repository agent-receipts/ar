package audit

import "testing"

func TestClassifyOperation(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"read_file", "read"},
		{"list_directory", "read"},
		{"list_issues", "read"},
		{"create_issue", "write"},
		{"update_record", "write"},
		{"delete_file", "delete"},
		{"remove_user", "delete"},
		{"run_query", "execute"},
		{"exec_command", "execute"},
		{"some_random_tool", "unknown"},

		// Resource-first naming (e.g. github-mcp-server).
		{"pull_request_read", "read"},
		{"pull_request_create", "write"},
		{"pull_request_update", "write"},
		{"repository_delete", "delete"},
		{"repository_remove", "delete"},
		{"workflow_run", "execute"},
		{"command_exec", "execute"},
		{"file_write", "write"},

		// Ambiguous: `_read` appears mid-name but name ends with `_mode`,
		// so this must not match the `_read` suffix.
		{"repository_read_only_mode", "unknown"},
	}
	for _, tt := range tests {
		got := ClassifyOperation(tt.tool)
		if got != tt.want {
			t.Errorf("ClassifyOperation(%q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

func TestScoreRisk(t *testing.T) {
	// Simple read: 0.
	score, _ := ScoreRisk("read_file", nil)
	if score != 0 {
		t.Errorf("read_file: expected 0, got %d", score)
	}

	// Write: 20.
	score, _ = ScoreRisk("create_issue", nil)
	if score != 20 {
		t.Errorf("create_issue: expected 20, got %d", score)
	}

	// Delete: 40.
	score, _ = ScoreRisk("delete_file", nil)
	if score != 40 {
		t.Errorf("delete_file: expected 40, got %d", score)
	}

	// Auth tool (write 20 + sensitive 30 + config modification 20): 70.
	score, _ = ScoreRisk("update_auth_config", nil)
	if score != 70 {
		t.Errorf("update_auth_config: expected 70, got %d", score)
	}

	// Capped at 100.
	score, _ = ScoreRisk("delete_auth_config", map[string]any{
		"query": "drop table secrets",
	})
	if score != 100 {
		t.Errorf("delete_auth_config with SQL: expected 100, got %d", score)
	}
}

// TestScoreRisk_SQLMutationHeuristic covers the false-positive fix: the SQL
// mutation check must only fire on values under SQL-context keys (sql, query,
// statement, command), not on arbitrary prose that happens to contain mutation
// keywords.
func TestScoreRisk_SQLMutationHeuristic(t *testing.T) {
	sqlMutationReason := "SQL mutation without WHERE clause"

	containsReason := func(reasons []string, r string) bool {
		for _, s := range reasons {
			if s == r {
				return true
			}
		}
		return false
	}

	// 1. create_pull_request with a title containing "update" — write only (20),
	//    the SQL mutation reason must NOT appear.
	score, reasons := ScoreRisk("create_pull_request", map[string]any{
		"title": "docs: update ecosystem framing",
		"body":  "This PR updates the ecosystem section.",
	})
	if score != 20 {
		t.Errorf("create_pull_request with prose title: expected score 20, got %d", score)
	}
	if containsReason(reasons, sqlMutationReason) {
		t.Errorf("create_pull_request with prose title: SQL mutation reason must not be present, reasons=%v", reasons)
	}

	// 2. Tool with {"query": "UPDATE users SET x=1"} — no WHERE, should add +30.
	score, reasons = ScoreRisk("run_query", map[string]any{
		"query": "UPDATE users SET x=1",
	})
	// run_query is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("run_query UPDATE without WHERE: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("run_query UPDATE without WHERE: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 3. Tool with {"query": "UPDATE users SET x=1 WHERE id=1"} — has WHERE, should NOT add +30.
	score, _ = ScoreRisk("run_query", map[string]any{
		"query": "UPDATE users SET x=1 WHERE id=1",
	})
	// run_query is execute (+30), no extra SQL mutation
	if score != 30 {
		t.Errorf("run_query UPDATE with WHERE: expected 30, got %d", score)
	}

	// 4. Tool with {"sql": "DROP TABLE foo"} — should trigger +30.
	score, reasons = ScoreRisk("exec_command", map[string]any{
		"sql": "DROP TABLE foo",
	})
	// exec_command is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("exec_command DROP TABLE: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("exec_command DROP TABLE: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 5. Nested args {"params": {"statement": "DELETE FROM t"}} — should trigger.
	score, reasons = ScoreRisk("run_query", map[string]any{
		"params": map[string]any{
			"statement": "DELETE FROM t",
		},
	})
	// run_query is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("nested statement DELETE: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("nested statement DELETE: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 6. Tool with {"title": "docs: delete stale section", "body": "…"} — should NOT trigger.
	score, reasons = ScoreRisk("create_pull_request", map[string]any{
		"title": "docs: delete stale section",
		"body":  "Removes outdated content.",
	})
	// create_pull_request is write (+20), no SQL mutation
	if score != 20 {
		t.Errorf("create_pull_request prose delete title: expected 20, got %d", score)
	}
	if containsReason(reasons, sqlMutationReason) {
		t.Errorf("create_pull_request prose delete title: SQL mutation reason must not be present, reasons=%v", reasons)
	}

	// 7. Array recursion: {"batch": [{"query": "UPDATE users SET x=1"}]} — should trigger.
	score, reasons = ScoreRisk("run_query", map[string]any{
		"batch": []any{
			map[string]any{"query": "UPDATE users SET x=1"},
		},
	})
	// run_query is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("array batch UPDATE: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("array batch UPDATE: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 8. Nested map-in-array: {"params": {"items": [{"sql": "DROP TABLE foo"}]}} — should trigger.
	score, reasons = ScoreRisk("exec_command", map[string]any{
		"params": map[string]any{
			"items": []any{
				map[string]any{"sql": "DROP TABLE foo"},
			},
		},
	})
	// exec_command is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("nested map-in-array DROP: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("nested map-in-array DROP: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 9. "somewhere" must not suppress the mutation signal —
	//    {"query": "UPDATE users SET note='find somewhere else'"} should trigger.
	score, reasons = ScoreRisk("run_query", map[string]any{
		"query": "UPDATE users SET note='find somewhere else'",
	})
	// run_query is execute (+30) + SQL mutation (+30) = 60
	if score != 60 {
		t.Errorf("UPDATE with 'somewhere' in value: expected 60, got %d", score)
	}
	if !containsReason(reasons, sqlMutationReason) {
		t.Errorf("UPDATE with 'somewhere' in value: SQL mutation reason must be present, reasons=%v", reasons)
	}

	// 10. Real WHERE clause still suppresses — uppercase.
	score, _ = ScoreRisk("run_query", map[string]any{
		"query": "UPDATE users SET x=1 WHERE id=1",
	})
	// run_query is execute (+30) only
	if score != 30 {
		t.Errorf("UPDATE with uppercase WHERE: expected 30, got %d", score)
	}

	// 11. Real where clause still suppresses — lowercase.
	score, _ = ScoreRisk("run_query", map[string]any{
		"query": "UPDATE users SET x=1 where id=1",
	})
	// run_query is execute (+30) only
	if score != 30 {
		t.Errorf("UPDATE with lowercase where: expected 30, got %d", score)
	}
}
