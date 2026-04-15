package proxy

import (
	"encoding/json"
	"testing"
)

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
