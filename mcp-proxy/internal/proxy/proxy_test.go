package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestNew(t *testing.T) {
	p := New("test-cmd", []string{"arg1", "arg2"}, nil)
	if p.command != "test-cmd" {
		t.Errorf("command = %q, want %q", p.command, "test-cmd")
	}
	if len(p.args) != 2 || p.args[0] != "arg1" {
		t.Errorf("args = %v, want [arg1 arg2]", p.args)
	}
}

func TestNewWithHandler(t *testing.T) {
	handler := func(direction string, raw []byte, msg *Message) *HandlerResult {
		return nil
	}
	p := New("test-cmd", []string{}, handler)
	if p.handler == nil {
		t.Error("handler not set")
	}
}

func TestMakeErrorResponse(t *testing.T) {
	resp := MakeErrorResponse(json.RawMessage(`1`), -32002, "denied")

	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	errObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", got["error"])
	}

	if errObj["code"] != float64(-32002) {
		t.Errorf("code = %v, want -32002", errObj["code"])
	}
	if errObj["message"] != "denied" {
		t.Errorf("message = %q, want %q", errObj["message"], "denied")
	}

	if errObj["data"] != nil {
		t.Errorf("expected no data field, got %v", errObj["data"])
	}
}

func TestMakeErrorResponseWithData(t *testing.T) {
	resp := MakeErrorResponseWithData(json.RawMessage(`1`), -32002, "denied", map[string]any{
		"status": "timed_out",
		"rule":   "pause_high_risk",
	})

	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	errObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", got["error"])
	}

	data, ok := errObj["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected error data object, got %T", errObj["data"])
	}

	if data["status"] != "timed_out" {
		t.Fatalf("expected status %q, got %v", "timed_out", data["status"])
	}
}

func TestMakeErrorResponseWithNilID(t *testing.T) {
	resp := MakeErrorResponse(nil, -32600, "Invalid Request")

	var got map[string]any
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if got["id"] != nil {
		t.Errorf("expected id=null for nil request, got %v", got["id"])
	}
}

func TestWriteToClientConcurrent(t *testing.T) {
	var buf bytes.Buffer
	p := &Proxy{
		clientWriter: &buf,
	}

	// Simulate concurrent writes
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			data := []byte(`{"jsonrpc":"2.0","id":1}`)
			done <- p.writeToClient(data)
		}(i)
	}

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("writeToClient: %v", err)
		}
	}

	// Should have 2 lines in buffer
	lines := bytes.Count(buf.Bytes(), []byte{'\n'})
	if lines != 2 {
		t.Errorf("expected 2 lines in buffer, got %d", lines)
	}
}

func TestWriteToClientWriteError(t *testing.T) {
	p := &Proxy{
		clientWriter: &failingWriter{},
	}

	err := p.writeToClient([]byte(`test`))
	if err == nil {
		t.Error("expected write error, got nil")
	}
}

type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestRunAlreadyStarted(t *testing.T) {
	p := New("true", nil, nil)
	// First call to startOnce.Do will set firstCall to true
	p.startOnce.Do(func() {})

	err := p.Run()
	if err == nil {
		t.Error("expected error for already-started proxy")
	}
	if err.Error() != "proxy already started" {
		t.Errorf("error = %q, want %q", err.Error(), "proxy already started")
	}
}

func TestMakeErrorResponseJSONValid(t *testing.T) {
	cases := []struct {
		name string
		id   json.RawMessage
		code int
		msg  string
	}{
		{"string id", json.RawMessage(`"req1"`), -32700, "Parse error"},
		{"number id", json.RawMessage(`42`), -32600, "Invalid Request"},
		{"null id", nil, -32601, "Method not found"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := MakeErrorResponse(c.id, c.code, c.msg)
			if !json.Valid(resp) {
				t.Errorf("invalid JSON response: %s", string(resp))
			}

			var got map[string]any
			if err := json.Unmarshal(resp, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if got["jsonrpc"] != "2.0" {
				t.Errorf("jsonrpc = %v, want 2.0", got["jsonrpc"])
			}
		})
	}
}
