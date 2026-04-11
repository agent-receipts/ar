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
