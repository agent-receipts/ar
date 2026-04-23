package audit

import (
	"regexp"
	"strings"
)

// whereClauseRe matches the SQL keyword "where" with token boundaries, so
// words like "somewhere" or "whereabouts" do not falsely suppress the
// mutation signal. Case-insensitive; boundaries are start/end of string or
// any non-letter character.
var whereClauseRe = regexp.MustCompile(`(?i)(^|[^a-z])where([^a-z]|$)`)

// ClassifyOperation determines the operation type from a tool name.
func ClassifyOperation(toolName string) string {
	lower := strings.ToLower(toolName)

	// Check in order: delete > execute > write > read.
	deletePrefixes := []string{"delete_", "remove_", "drop_", "destroy_", "purge_"}
	for _, p := range deletePrefixes {
		if strings.HasPrefix(lower, p) {
			return "delete"
		}
	}

	execPrefixes := []string{"run_", "exec_", "invoke_", "call_", "trigger_"}
	for _, p := range execPrefixes {
		if strings.HasPrefix(lower, p) {
			return "execute"
		}
	}

	writePrefixes := []string{"create_", "update_", "set_", "add_", "put_", "edit_", "modify_", "write_"}
	for _, p := range writePrefixes {
		if strings.HasPrefix(lower, p) {
			return "write"
		}
	}

	readPrefixes := []string{"get_", "read_", "list_", "search_", "describe_", "show_"}
	for _, p := range readPrefixes {
		if strings.HasPrefix(lower, p) {
			return "read"
		}
	}

	// Suffix checks cover resource-first naming like `pull_request_read`
	// (github-mcp-server) where the action word trails the resource.
	deleteSuffixes := []string{"_delete", "_remove"}
	for _, s := range deleteSuffixes {
		if strings.HasSuffix(lower, s) {
			return "delete"
		}
	}

	execSuffixes := []string{"_run", "_exec"}
	for _, s := range execSuffixes {
		if strings.HasSuffix(lower, s) {
			return "execute"
		}
	}

	writeSuffixes := []string{"_create", "_update", "_write"}
	for _, s := range writeSuffixes {
		if strings.HasSuffix(lower, s) {
			return "write"
		}
	}

	if strings.HasSuffix(lower, "_read") {
		return "read"
	}

	return "unknown"
}

// sqlValContainsMutation walks args recursively and returns true when a value
// stored under a SQL-context key (sql, query, statement, command) contains one
// of the mutation keywords but does NOT contain "where". This scoping prevents
// natural-English prose in unrelated argument fields from tripping the check.
func sqlValContainsMutation(args map[string]any, sqlContextKeys, mutations []string) bool {
	for k, v := range args {
		kLower := strings.ToLower(k)
		switch val := v.(type) {
		case string:
			for _, ctxKey := range sqlContextKeys {
				if kLower == ctxKey {
					s := strings.ToLower(val)
					// Token-boundary check: "somewhere" / "whereabouts"
					// must not count as a WHERE clause.
					if whereClauseRe.MatchString(s) {
						break
					}
					for _, m := range mutations {
						if strings.Contains(s, m) {
							return true
						}
					}
					break
				}
			}
		case map[string]any:
			// Recurse into nested argument objects.
			if sqlValContainsMutation(val, sqlContextKeys, mutations) {
				return true
			}
		case []any:
			// Recurse into arrays: SQL-context keys may live inside list
			// elements (e.g. batch: [{"query": "..."}, ...]).
			if sqlSliceContainsMutation(val, sqlContextKeys, mutations) {
				return true
			}
		}
	}
	return false
}

// sqlSliceContainsMutation walks a []any and recurses into each element,
// delegating maps to sqlValContainsMutation and slices back to itself.
func sqlSliceContainsMutation(arr []any, sqlContextKeys, mutations []string) bool {
	for _, item := range arr {
		switch v := item.(type) {
		case map[string]any:
			if sqlValContainsMutation(v, sqlContextKeys, mutations) {
				return true
			}
		case []any:
			if sqlSliceContainsMutation(v, sqlContextKeys, mutations) {
				return true
			}
		}
	}
	return false
}

// ScoreRisk computes a risk score (0-100) for a tool call.
func ScoreRisk(toolName string, arguments map[string]any) (int, []string) {
	score := 0
	var reasons []string

	lower := strings.ToLower(toolName)
	op := ClassifyOperation(toolName)

	// Base score by operation type.
	switch op {
	case "read":
		// 0
	case "write":
		score += 20
		reasons = append(reasons, "write operation")
	case "delete":
		score += 40
		reasons = append(reasons, "delete operation")
	case "execute":
		score += 30
		reasons = append(reasons, "execute operation")
	default:
		score += 10
		reasons = append(reasons, "unknown operation type")
	}

	// Check for sensitive keywords in tool name.
	sensitiveKeywords := []string{"auth", "credential", "password", "token", "secret", "key"}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			score += 30
			reasons = append(reasons, "touches sensitive data ("+kw+")")
			break
		}
	}

	// Check for SQL mutation without WHERE clause.
	// We only inspect values that live under SQL-context keys (sql, query,
	// statement, command) to avoid false-positives when natural-English prose
	// in unrelated fields (e.g. a PR title containing "update") matches the
	// mutation keywords.
	if arguments != nil {
		sqlContextKeys := []string{"sql", "query", "statement", "command"}
		sqlMutations := []string{"drop ", "delete ", "update ", "truncate ", "alter "}
		if sqlValContainsMutation(arguments, sqlContextKeys, sqlMutations) {
			score += 30
			reasons = append(reasons, "SQL mutation without WHERE clause")
		}
	}

	// Config modification.
	if strings.Contains(lower, "config") || strings.Contains(lower, "setting") {
		score += 20
		reasons = append(reasons, "modifies configuration")
	}

	// External messaging.
	if strings.HasPrefix(lower, "send_") || strings.HasPrefix(lower, "post_") {
		score += 15
		reasons = append(reasons, "sends external message")
	}

	if score > 100 {
		score = 100
	}

	return score, reasons
}
