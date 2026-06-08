package main

import (
	"encoding/json"
	"errors"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// claudeCodeFrame is the JSON envelope Claude Code sends on stdin for
// PostToolUse and PreToolUse hooks.
type claudeCodeFrame struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	ToolUseID     string          `json:"tool_use_id"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
}

// readClaudeCode parses a Claude Code PostToolUse or PreToolUse stdin frame
// and maps it to an emitter.Event. The decision is derived from the
// hook_event_name field:
//   - "PostToolUse" → "allowed" (tool ran successfully)
//   - "PreToolUse"  → "pending" (tool is about to run; outcome not yet known)
//
// The returned sessionID is the host-supplied session identifier from the
// frame; it is the empty string when absent.
func readClaudeCode(stdin []byte, _ func(string) string) (emitter.Event, string, error) {
	if len(stdin) == 0 {
		return emitter.Event{}, "", errors.New("empty stdin")
	}
	var f claudeCodeFrame
	if err := json.Unmarshal(stdin, &f); err != nil {
		return emitter.Event{}, "", err
	}
	if f.ToolName == "" {
		return emitter.Event{}, "", errors.New("missing tool_name")
	}

	var decision string
	switch f.HookEventName {
	case "PostToolUse":
		decision = "allowed"
	case "PreToolUse":
		decision = "pending"
	default:
		// hook_event_name absent or unrecognised — fall back to "allowed" for
		// backward compatibility with payloads that omit the field (e.g. runtimes
		// that set CLAUDE_SESSION_ID but do not include hook_event_name).
		decision = "allowed"
	}

	ev := emitter.Event{
		Channel:       "claude-code",
		Tool:          emitter.Tool{Name: f.ToolName},
		Decision:      decision,
		CorrelationID: f.ToolUseID,
	}
	// Only set Input/Output when non-empty; the emitter rejects non-nil empty
	// slices and the daemon expects nil to mean "no payload".
	if len(f.ToolInput) > 0 {
		ev.Input = f.ToolInput
	}
	if len(f.ToolResponse) > 0 {
		ev.Output = f.ToolResponse
	}

	return ev, f.SessionID, nil
}
