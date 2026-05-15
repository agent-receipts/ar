package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// --- readClaudeCode unit tests ---

func TestReadClaudeCode(t *testing.T) {
	validInput := json.RawMessage(`{"command":"go test ./..."}`)
	validResponse := json.RawMessage(`{"output":"ok","exit_code":0}`)

	tests := []struct {
		name      string
		stdin     string
		wantErr   bool
		wantTool  string
		wantSID   string
		wantInput bool
		wantOut   bool
	}{
		{
			name: "full frame",
			stdin: `{
				"session_id": "sess-abc",
				"tool_name": "Bash",
				"tool_input": {"command":"go test ./..."},
				"tool_response": {"output":"ok","exit_code":0}
			}`,
			wantTool:  "Bash",
			wantSID:   "sess-abc",
			wantInput: true,
			wantOut:   true,
		},
		{
			name: "no session_id",
			stdin: `{
				"tool_name": "Read",
				"tool_input": {"file_path":"/etc/hosts"},
				"tool_response": {"content":"127.0.0.1 localhost"}
			}`,
			wantTool:  "Read",
			wantSID:   "",
			wantInput: true,
			wantOut:   true,
		},
		{
			name: "no tool_input",
			stdin: `{
				"session_id": "s1",
				"tool_name": "WebSearch",
				"tool_response": {"results":[]}
			}`,
			wantTool:  "WebSearch",
			wantSID:   "s1",
			wantInput: false,
			wantOut:   true,
		},
		{
			name: "no tool_response",
			stdin: `{
				"session_id": "s2",
				"tool_name": "Write",
				"tool_input": {"file_path":"x.go","content":"package main"}
			}`,
			wantTool:  "Write",
			wantSID:   "s2",
			wantInput: true,
			wantOut:   false,
		},
		{
			name:    "missing tool_name",
			stdin:   `{"session_id":"s3","tool_input":{},"tool_response":{}}`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			stdin:   `not json at all`,
			wantErr: true,
		},
		{
			name:    "empty stdin",
			stdin:   ``,
			wantErr: true,
		},
		{
			name: "oversized payload (within emitter limit) passes readClaudeCode",
			stdin: func() string {
				// Build a frame with a large but valid JSON input.
				val := strings.Repeat("x", 100)
				f := map[string]any{
					"session_id":    "big",
					"tool_name":     "Bash",
					"tool_input":    map[string]string{"command": val},
					"tool_response": map[string]string{"output": val},
				}
				b, _ := json.Marshal(f)
				return string(b)
			}(),
			wantTool:  "Bash",
			wantSID:   "big",
			wantInput: true,
			wantOut:   true,
		},
	}

	_ = validInput
	_ = validResponse

	noEnv := func(string) string { return "" }

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, sid, err := readClaudeCode([]byte(tt.stdin), noEnv)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Channel != "claude-code" {
				t.Errorf("Channel = %q; want claude-code", ev.Channel)
			}
			if ev.Tool.Name != tt.wantTool {
				t.Errorf("Tool.Name = %q; want %q", ev.Tool.Name, tt.wantTool)
			}
			if ev.Tool.Server != "" {
				t.Errorf("Tool.Server = %q; want empty", ev.Tool.Server)
			}
			if ev.Decision != "allowed" {
				t.Errorf("Decision = %q; want allowed", ev.Decision)
			}
			if sid != tt.wantSID {
				t.Errorf("sessionID = %q; want %q", sid, tt.wantSID)
			}
			if tt.wantInput && ev.Input == nil {
				t.Error("Input is nil; want non-nil")
			}
			if !tt.wantInput && ev.Input != nil {
				t.Errorf("Input = %s; want nil", ev.Input)
			}
			if tt.wantOut && ev.Output == nil {
				t.Error("Output is nil; want non-nil")
			}
			if !tt.wantOut && ev.Output != nil {
				t.Errorf("Output = %s; want nil", ev.Output)
			}
		})
	}
}

// TestReadClaudeCode_InputOutputAreValidJSON asserts the returned Input and
// Output are valid JSON when present.
func TestReadClaudeCode_InputOutputAreValidJSON(t *testing.T) {
	stdin := `{
		"session_id": "v",
		"tool_name": "Edit",
		"tool_input": {"file_path":"a.go","old_string":"x","new_string":"y"},
		"tool_response": {"success":true}
	}`
	ev, _, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}
	if !json.Valid(ev.Input) {
		t.Errorf("Input is not valid JSON: %s", ev.Input)
	}
	if !json.Valid(ev.Output) {
		t.Errorf("Output is not valid JSON: %s", ev.Output)
	}
}

// --- detect unit tests ---

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "CLAUDE_SESSION_ID set",
			env:  map[string]string{"CLAUDE_SESSION_ID": "abc"},
			want: "claude-code",
		},
		{
			name: "no known env vars",
			env:  map[string]string{},
			want: "",
		},
		{
			name: "unrelated env var",
			env:  map[string]string{"HOME": "/home/user"},
			want: "",
		},
		{
			name: "CLAUDE_SESSION_ID empty string",
			env:  map[string]string{"CLAUDE_SESSION_ID": ""},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detect(func(k string) string { return tt.env[k] })
			if got != tt.want {
				t.Errorf("detect() = %q; want %q", got, tt.want)
			}
		})
	}
}

// --- emitter.Event compatibility tests ---

// TestReadClaudeCode_EventAcceptedByEmitter verifies that the emitter.Event
// produced by readClaudeCode satisfies the emitter's validation rules (channel,
// tool.name, decision, valid JSON). This catches mismatches before the emitter
// rejects the frame at emit time.
func TestReadClaudeCode_EventAcceptedByEmitter(t *testing.T) {
	stdin := `{
		"session_id": "compat-test",
		"tool_name": "Bash",
		"tool_input": {"command":"echo hello"},
		"tool_response": {"output":"hello\n","exit_code":0}
	}`
	ev, _, err := readClaudeCode([]byte(stdin), func(string) string { return "" })
	if err != nil {
		t.Fatalf("readClaudeCode: %v", err)
	}

	// Replicate the emitter's validation rules without dialling a socket.
	if ev.Channel == "" {
		t.Error("Channel is empty; emitter would reject")
	}
	if ev.Tool.Name == "" {
		t.Error("Tool.Name is empty; emitter would reject")
	}
	switch ev.Decision {
	case "allowed", "denied", "pending":
	default:
		t.Errorf("Decision %q not in allowed set; emitter would reject", ev.Decision)
	}
	if ev.Input != nil && len(ev.Input) == 0 {
		t.Error("Input is non-nil empty slice; emitter would reject")
	}
	if ev.Output != nil && len(ev.Output) == 0 {
		t.Error("Output is non-nil empty slice; emitter would reject")
	}
	if ev.Input != nil && !json.Valid(ev.Input) {
		t.Errorf("Input is not valid JSON: %s", ev.Input)
	}
	if ev.Output != nil && !json.Valid(ev.Output) {
		t.Errorf("Output is not valid JSON: %s", ev.Output)
	}

	// Sanity-check emitter.Tool type is used (compile-time check embedded here).
	var _ emitter.Tool = ev.Tool
}
