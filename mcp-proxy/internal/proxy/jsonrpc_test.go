package proxy

import (
	"testing"
)

func TestParseMessage(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if msg.Method != "tools/call" {
		t.Errorf("expected tools/call, got %s", msg.Method)
	}
	if !msg.IsRequest() {
		t.Error("expected request")
	}
	if !msg.IsToolCall() {
		t.Error("expected tool call")
	}

	params, err := msg.ParseToolCallParams()
	if err != nil {
		t.Fatal(err)
	}
	if params.Name != "read_file" {
		t.Errorf("expected read_file, got %s", params.Name)
	}
}

func TestParseMessageResponse(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"hello"}}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if !msg.IsResponse() {
		t.Error("expected response")
	}
	if msg.IsRequest() {
		t.Error("should not be request")
	}
}

func TestParseMessageInvalid(t *testing.T) {
	if msg := ParseMessage([]byte("not json")); msg != nil {
		t.Error("expected nil for invalid JSON")
	}
	if msg := ParseMessage([]byte(`{"jsonrpc":"1.0"}`)); msg != nil {
		t.Error("expected nil for wrong jsonrpc version")
	}
}

func TestParseToolCallParamsNil(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	params, err := msg.ParseToolCallParams()
	if err != nil {
		t.Fatal(err)
	}
	if params == nil {
		t.Fatal("expected non-nil params for nil Params field")
	}
	if params.Name != "" {
		t.Errorf("expected empty name, got %s", params.Name)
	}
}

func TestParseMessageNotification(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil")
	}
	if !msg.IsNotification() {
		t.Error("expected notification")
	}
}

func TestIDStringWithStringID(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"test"}}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	if got := msg.IDString(); got != "abc" {
		t.Errorf("expected IDString() = %q, got %q", "abc", got)
	}
}

func TestParseMessageNullID(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":null,"result":{}}`)
	msg := ParseMessage(line)
	if msg == nil {
		t.Fatal("expected non-nil message")
	}
	// id is present in JSON (as null), so RawMessage is non-nil (contains "null").
	if msg.ID == nil {
		t.Error("expected ID to be non-nil (JSON null)")
	}
}

func TestStripMCPPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"mcp__github-audited__merge_pull_request", "merge_pull_request"},
		{"mcp__github-audited__create_pull_request", "create_pull_request"},
		{"mcp__some-server__read_file", "read_file"},
		{"read_file", "read_file"},
		{"mcp__malformed", "mcp__malformed"},
		{"", ""},
		{"mcp____tool", "tool"},
		{"mcp__server__", "mcp__server__"},
	}
	for _, tt := range tests {
		got := StripMCPPrefix(tt.input)
		if got != tt.want {
			t.Errorf("StripMCPPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseMessageBatchReturnsNil(t *testing.T) {
	line := []byte(`[{"jsonrpc":"2.0","id":1,"method":"test"}]`)
	msg := ParseMessage(line)
	if msg != nil {
		t.Error("expected nil for batch (JSON array) message")
	}
}

func TestToolUseID(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   string
	}{
		{
			name:   "string value extracted",
			params: `{"name":"t","_meta":{"claudecode/toolUseId":"toolu_01ABC"}}`,
			want:   "toolu_01ABC",
		},
		{
			name:   "absent _meta returns empty",
			params: `{"name":"t"}`,
			want:   "",
		},
		{
			name:   "missing key returns empty",
			params: `{"name":"t","_meta":{"other":"x"}}`,
			want:   "",
		},
		{
			name:   "non-string value returns empty (no parse failure)",
			params: `{"name":"t","_meta":{"claudecode/toolUseId":12345}}`,
			want:   "",
		},
		{
			name:   "null value returns empty (no parse failure)",
			params: `{"name":"t","_meta":{"claudecode/toolUseId":null}}`,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + tt.params + `}`)
			msg := ParseMessage(line)
			if msg == nil {
				t.Fatal("expected non-nil message")
			}
			p, err := msg.ParseToolCallParams()
			if err != nil {
				t.Fatalf("ParseToolCallParams error: %v", err)
			}
			if got := p.ToolUseID(); got != tt.want {
				t.Errorf("ToolUseID() = %q, want %q", got, tt.want)
			}
		})
	}
}
