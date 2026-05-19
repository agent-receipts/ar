//go:build linux

package host

import (
	"os"
	"testing"
)

func TestDetect_KnownHosts(t *testing.T) {
	cases := []struct {
		comm         string
		wantName     string
		wantOperator string
		wantOperID   string
		wantSource   string
	}{
		{"claude", "Claude Code", "Anthropic", "did:web:anthropic.com", "auto:claude"},
		{"codex", "Codex", "OpenAI", "did:web:openai.com", "auto:codex"},
		{"cursor", "Cursor", "Cursor", "did:web:cursor.com", "auto:cursor"},
		{"windsurf", "Windsurf", "Codeium", "did:web:codeium.com", "auto:windsurf"},
	}
	for _, tc := range cases {
		t.Run(tc.comm, func(t *testing.T) {
			orig := readComm
			readComm = func(_ int) (string, error) { return tc.comm, nil }
			t.Cleanup(func() { readComm = orig })

			id := Detect()
			if id.IssuerName != tc.wantName {
				t.Errorf("IssuerName = %q, want %q", id.IssuerName, tc.wantName)
			}
			if id.OperatorName != tc.wantOperator {
				t.Errorf("OperatorName = %q, want %q", id.OperatorName, tc.wantOperator)
			}
			if id.OperatorID != tc.wantOperID {
				t.Errorf("OperatorID = %q, want %q", id.OperatorID, tc.wantOperID)
			}
			if id.Source != tc.wantSource {
				t.Errorf("Source = %q, want %q", id.Source, tc.wantSource)
			}
			if id.IssuerModel != "" {
				t.Errorf("IssuerModel = %q, want empty", id.IssuerModel)
			}
		})
	}
}

func TestDetect_UnknownHost(t *testing.T) {
	orig := readComm
	readComm = func(_ int) (string, error) { return "vscode", nil }
	t.Cleanup(func() { readComm = orig })

	id := Detect()
	if id.Source != "unknown" {
		t.Errorf("Source = %q, want \"unknown\"", id.Source)
	}
	if id.IssuerName != "" || id.OperatorName != "" || id.OperatorID != "" {
		t.Errorf("expected empty identity for unknown host, got %+v", id)
	}
}

func TestDetect_ReadCommError(t *testing.T) {
	orig := readComm
	readComm = func(_ int) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { readComm = orig })

	id := Detect()
	if id.Source != "unknown" {
		t.Errorf("Source = %q, want \"unknown\"", id.Source)
	}
	if id.IssuerName != "" {
		t.Errorf("IssuerName = %q, want empty on read error", id.IssuerName)
	}
	if id.IssuerModel != "" {
		t.Errorf("IssuerModel = %q, want empty on read error", id.IssuerModel)
	}
	if id.OperatorID != "" {
		t.Errorf("OperatorID = %q, want empty on read error", id.OperatorID)
	}
	if id.OperatorName != "" {
		t.Errorf("OperatorName = %q, want empty on read error", id.OperatorName)
	}
}
