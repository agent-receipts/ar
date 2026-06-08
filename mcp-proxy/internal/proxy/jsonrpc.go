package proxy

import (
	"encoding/json"
	"strings"
)

// Message represents a parsed JSON-RPC 2.0 message.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ToolCallParams holds parsed params for a tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	// Meta holds the MCP _meta field. Claude Code populates
	// _meta["claudecode/toolUseId"] with the tool_use_id from the hook payload,
	// enabling correlation between hook pre-check receipts and proxy post-action
	// receipts for the same logical tool invocation.
	// Typed as map[string]any (not map[string]string) so that non-string values
	// in _meta do not cause json.Unmarshal to fail and silently bypass policy.
	Meta map[string]any `json:"_meta,omitempty"`
}

// ToolUseID returns the Claude Code tool_use_id from _meta, or empty string
// if absent or not a string. This is the correlation key linking a hook
// receipt to its paired proxy receipt.
func (p *ToolCallParams) ToolUseID() string {
	if p.Meta == nil {
		return ""
	}
	v, ok := p.Meta["claudecode/toolUseId"]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// ParseMessage attempts to parse a JSON-RPC message from a line.
// Returns nil if the line is not valid JSON-RPC.
func ParseMessage(line []byte) *Message {
	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil
	}
	if msg.JSONRPC != "2.0" {
		return nil
	}
	return &msg
}

// IsRequest returns true if the message is a request (has method).
func (m *Message) IsRequest() bool {
	return m.Method != "" && m.ID != nil
}

// IsResponse returns true if the message is a response (has result or error).
func (m *Message) IsResponse() bool {
	return m.Method == "" && m.ID != nil
}

// IsNotification returns true if the message is a notification (method but no id).
func (m *Message) IsNotification() bool {
	return m.Method != "" && m.ID == nil
}

// IsToolCall returns true if this is a tools/call request.
func (m *Message) IsToolCall() bool {
	return m.Method == "tools/call" && m.IsRequest()
}

// ParseToolCallParams extracts tool name and arguments from a tools/call request.
// Returns a zero-value ToolCallParams (empty name) if params are nil or missing,
// so callers always get a non-nil result for tool calls.
func (m *Message) ParseToolCallParams() (*ToolCallParams, error) {
	if m.Params == nil {
		return &ToolCallParams{}, nil
	}
	var p ToolCallParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// StripMCPPrefix removes the MCP server prefix from a tool name.
// Tool names from MCP clients arrive as "mcp__<server>__<tool>" but downstream
// classification and receipts should use the bare tool name.
func StripMCPPrefix(name string) string {
	if !strings.HasPrefix(name, "mcp__") {
		return name
	}
	// Find the second "__" separator after "mcp__".
	rest := name[len("mcp__"):]
	idx := strings.Index(rest, "__")
	if idx < 0 {
		return name
	}
	tool := rest[idx+len("__"):]
	if tool == "" {
		return name
	}
	return tool
}

// IDString returns the message ID as a normalized string for matching purposes.
// Strips surrounding quotes from JSON string IDs so "1" and 1 both work as map keys.
func (m *Message) IDString() string {
	if m.ID == nil {
		return ""
	}
	raw := string(m.ID)
	// Try to unmarshal as a string first (JSON string IDs).
	var s string
	if err := json.Unmarshal(m.ID, &s); err == nil {
		return s
	}
	// Otherwise return the raw JSON (numeric IDs, etc.).
	return raw
}
