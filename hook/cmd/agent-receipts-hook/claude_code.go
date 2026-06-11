package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// claudeCodeFrame is the JSON envelope Claude Code sends on stdin for
// PostToolUse and PreToolUse hooks.
type claudeCodeFrame struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	TranscriptPath string          `json:"transcript_path"`
}

// readClaudeCode parses a Claude Code PostToolUse or PreToolUse stdin frame
// and maps it to an emitter.Event. The decision is derived from the
// hook_event_name field:
//   - "PostToolUse" → "allowed" (tool ran successfully)
//   - "PreToolUse"  → "pending" (tool is about to run; outcome not yet known)
//
// The returned sessionID is the host-supplied session identifier from the
// frame; it is the empty string when absent.
func readClaudeCode(stdin []byte, env func(string) string) (emitter.Event, string, error) {
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
		AgentID:       f.AgentID,
		AgentType:     f.AgentType,
	}
	// Only set Input/Output when non-empty; the emitter rejects non-nil empty
	// slices and the daemon expects nil to mean "no payload".
	if len(f.ToolInput) > 0 {
		ev.Input = f.ToolInput
	}
	if len(f.ToolResponse) > 0 {
		ev.Output = f.ToolResponse
	}

	// Enrich with the model and token usage for this tool call, read from the
	// session transcript (works with OTEL disabled — no proxy involved). This is
	// strictly best-effort: a missing transcript, an unmatched id, or a turn with
	// no usage object simply leaves the fields unset. Enrichment never fails the
	// hook, so lookup errors are swallowed rather than surfaced.
	if f.ToolUseID != "" {
		path := resolveTranscriptPath(f.TranscriptPath, f.SessionID, env)
		model, usage, found, lookupErr := lookupTranscriptUsage(path, f.ToolUseID)
		switch {
		case lookupErr != nil:
			// Enrichment is best-effort and must never fail the hook, but a
			// genuine read error (unreadable or corrupt transcript) is worth a
			// non-fatal note so it is not silently indistinguishable from a
			// tool_use_id that is simply absent. We do not exit non-zero.
			fmt.Fprintf(os.Stderr, "agent-receipts-hook: transcript enrichment skipped: %v\n", lookupErr)
		case found:
			ev.Model = model
			ev.Usage = usage
			ev.CaptureMethod = "transcript"
		}
	}

	return ev, f.SessionID, nil
}
