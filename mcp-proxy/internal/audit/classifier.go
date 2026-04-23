package audit

import (
	"encoding/json"
	"strings"
)

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

	// Check for SQL mutation without WHERE.
	if arguments != nil {
		argJSON, _ := json.Marshal(arguments)
		argStr := strings.ToLower(string(argJSON))
		sqlMutations := []string{"drop ", "delete ", "update ", "truncate ", "alter "}
		for _, m := range sqlMutations {
			if strings.Contains(argStr, m) && !strings.Contains(argStr, "where") {
				score += 30
				reasons = append(reasons, "SQL mutation without WHERE clause")
				break
			}
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
