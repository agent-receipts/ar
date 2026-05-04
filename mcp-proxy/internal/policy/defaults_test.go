package policy

import "testing"

// TestDefaultRulesStructure pins the shape of the built-in ruleset so that
// reordering, renaming, or accidentally disabling a default surfaces as a test
// failure.
func TestDefaultRulesStructure(t *testing.T) {
	rules := DefaultRules()

	wantNames := []string{
		"block_destructive_ops",
		"pause_high_risk",
		"flag_sql_mutations",
		"flag_auth_tools",
		"flag_config_changes",
		"flag_external_messages",
	}

	if len(rules) != len(wantNames) {
		t.Fatalf("DefaultRules: want %d rules, got %d", len(wantNames), len(rules))
	}

	for i, want := range wantNames {
		if rules[i].Name != want {
			t.Errorf("rule[%d].Name = %q, want %q", i, rules[i].Name, want)
		}
		if !rules[i].Enabled {
			t.Errorf("rule[%d] (%s) must ship enabled", i, rules[i].Name)
		}
		if rules[i].Action == "" {
			t.Errorf("rule[%d] (%s) has empty action", i, rules[i].Name)
		}
	}
}

// findRule returns the named default rule wrapped in a single-rule engine, so
// each test isolates one rule's matching behaviour from the others.
func findRule(t *testing.T, name string) *Engine {
	t.Helper()
	for _, r := range DefaultRules() {
		if r.Name == name {
			return NewEngine([]Rule{r})
		}
	}
	t.Fatalf("default rule %q not found", name)
	return nil
}

func TestDefaultBlockDestructiveOps(t *testing.T) {
	engine := findRule(t, "block_destructive_ops")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "delete tool, delete op, risk >= 70 → block",
			ctx:  EvalContext{ToolName: "delete_secrets", OperationType: "delete", RiskScore: 70},
			want: "block",
		},
		{
			name: "delete tool, delete op, risk above threshold → block",
			ctx:  EvalContext{ToolName: "delete_users", OperationType: "delete", RiskScore: 95},
			want: "block",
		},
		{
			name: "boundary: risk 69 (below 70) → pass",
			ctx:  EvalContext{ToolName: "delete_secrets", OperationType: "delete", RiskScore: 69},
			want: "pass",
		},
		{
			name: "wrong operation type (read) → pass even with high risk",
			ctx:  EvalContext{ToolName: "delete_secrets", OperationType: "read", RiskScore: 99},
			want: "pass",
		},
		{
			name: "non-delete tool, delete op, high risk → pass (tool pattern)",
			ctx:  EvalContext{ToolName: "remove_user", OperationType: "delete", RiskScore: 99},
			want: "pass",
		},
		{
			name: "case-insensitive tool match (DELETE_FILES) → block",
			ctx:  EvalContext{ToolName: "DELETE_FILES", OperationType: "delete", RiskScore: 80},
			want: "block",
		},
	}
	runDecisionCases(t, engine, tests)
}

func TestDefaultPauseHighRisk(t *testing.T) {
	engine := findRule(t, "pause_high_risk")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "risk 50 (boundary) → pause",
			ctx:  EvalContext{ToolName: "anything", RiskScore: 50},
			want: "pause",
		},
		{
			name: "risk 49 (below boundary) → pass",
			ctx:  EvalContext{ToolName: "anything", RiskScore: 49},
			want: "pass",
		},
		{
			name: "risk 100 → pause",
			ctx:  EvalContext{ToolName: "anything", RiskScore: 100},
			want: "pause",
		},
		{
			name: "no tool/server/op constraint applies — only risk matters",
			ctx:  EvalContext{ToolName: "ls", ServerName: "fs", OperationType: "read", RiskScore: 50},
			want: "pause",
		},
	}
	runDecisionCases(t, engine, tests)
}

func TestDefaultFlagSQLMutations(t *testing.T) {
	engine := findRule(t, "flag_sql_mutations")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "postgres write → flag",
			ctx:  EvalContext{ServerName: "postgres", OperationType: "write"},
			want: "flag",
		},
		{
			name: "postgres-prod (glob) delete → flag",
			ctx:  EvalContext{ServerName: "postgres-prod", OperationType: "delete"},
			want: "flag",
		},
		{
			name: "postgres execute → flag",
			ctx:  EvalContext{ServerName: "postgres", OperationType: "execute"},
			want: "flag",
		},
		{
			name: "postgres read → pass (not in operation_types)",
			ctx:  EvalContext{ServerName: "postgres", OperationType: "read"},
			want: "pass",
		},
		{
			name: "mysql write → pass (server doesn't match postgres*)",
			ctx:  EvalContext{ServerName: "mysql", OperationType: "write"},
			want: "pass",
		},
	}
	runDecisionCases(t, engine, tests)
}

func TestDefaultFlagAuthTools(t *testing.T) {
	engine := findRule(t, "flag_auth_tools")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "tool with auth substring → flag",
			ctx:  EvalContext{ToolName: "rotate_auth_token"},
			want: "flag",
		},
		{
			name: "tool ending in auth → flag",
			ctx:  EvalContext{ToolName: "check_auth"},
			want: "flag",
		},
		{
			name: "tool starting with auth → flag",
			ctx:  EvalContext{ToolName: "authorize_request"},
			want: "flag",
		},
		{
			name: "unrelated tool → pass",
			ctx:  EvalContext{ToolName: "read_file"},
			want: "pass",
		},
		{
			name: "case-insensitive AUTH → flag",
			ctx:  EvalContext{ToolName: "OAUTH_REFRESH"},
			want: "flag",
		},
	}
	runDecisionCases(t, engine, tests)
}

func TestDefaultFlagConfigChanges(t *testing.T) {
	engine := findRule(t, "flag_config_changes")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "config tool, write op → flag",
			ctx:  EvalContext{ToolName: "update_config", OperationType: "write"},
			want: "flag",
		},
		{
			name: "config tool, delete op → flag",
			ctx:  EvalContext{ToolName: "delete_config_key", OperationType: "delete"},
			want: "flag",
		},
		{
			name: "config tool, read op → pass (operation type filter)",
			ctx:  EvalContext{ToolName: "get_config", OperationType: "read"},
			want: "pass",
		},
		{
			name: "non-config tool, write op → pass",
			ctx:  EvalContext{ToolName: "save_user", OperationType: "write"},
			want: "pass",
		},
	}
	runDecisionCases(t, engine, tests)
}

func TestDefaultFlagExternalMessages(t *testing.T) {
	engine := findRule(t, "flag_external_messages")

	tests := []struct {
		name string
		ctx  EvalContext
		want string
	}{
		{
			name: "send_email → flag",
			ctx:  EvalContext{ToolName: "send_email"},
			want: "flag",
		},
		{
			name: "send_slack_message → flag",
			ctx:  EvalContext{ToolName: "send_slack_message"},
			want: "flag",
		},
		{
			name: "non-send tool → pass",
			ctx:  EvalContext{ToolName: "list_messages"},
			want: "pass",
		},
		{
			name: "send substring not at start → pass (glob requires send_ prefix)",
			ctx:  EvalContext{ToolName: "resend_message"},
			want: "pass",
		},
	}
	runDecisionCases(t, engine, tests)
}

// TestDefaultRulesNoApproverNeededWithoutPause verifies the convenience that
// HasPauseRules and Describe correctly identify the only pause rule shipped by
// default. Removing or repurposing pause_high_risk would make the proxy stop
// requiring an approver, which is a meaningful behaviour change.
func TestDefaultRulesNoApproverNeededWithoutPause(t *testing.T) {
	rules := DefaultRules()
	pruned := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Name == "pause_high_risk" {
			continue
		}
		pruned = append(pruned, r)
	}
	engine := NewEngine(pruned)
	if engine.HasPauseRules() {
		t.Fatal("removing pause_high_risk should leave no pause rules")
	}
	if engine.Describe().NeedsApprover() {
		t.Fatal("Describe().NeedsApprover() should be false without pause rules")
	}
}

// runDecisionCases is a shared table driver for per-rule decision tests.
func runDecisionCases(t *testing.T, engine *Engine, cases []struct {
	name string
	ctx  EvalContext
	want string
},
) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Evaluate(tc.ctx)
			if got.Action != tc.want {
				t.Errorf("Evaluate(%+v) = %s (rule=%s, reason=%q), want %s",
					tc.ctx, got.Action, got.RuleName, got.Reason, tc.want)
			}
		})
	}
}
