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

// noEnv stubs environ to an empty environment so env-marker detection is a
// no-op for tests that exercise only /proc behaviour.
func noEnv(t *testing.T) {
	t.Helper()
	orig := environ
	environ = func() []string { return nil }
	t.Cleanup(func() { environ = orig })
}

func TestDetect_UnknownHost(t *testing.T) {
	orig := readComm
	readComm = func(_ int) (string, error) { return "vscode", nil }
	t.Cleanup(func() { readComm = orig })
	noEnv(t)

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
	noEnv(t)

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

// unknownComm stubs /proc detection to a non-registry comm so detection falls
// through to the env-marker scan.
func unknownComm(t *testing.T) {
	t.Helper()
	orig := readComm
	readComm = func(_ int) (string, error) { return "bash", nil }
	t.Cleanup(func() { readComm = orig })
}

func TestDetect_EnvMarker(t *testing.T) {
	cases := []struct {
		name         string
		env          []string
		wantName     string
		wantOperator string
		wantOperID   string
		wantSource   string
	}{
		{"claude", []string{"CLAUDECODE=1"}, "Claude Code", "Anthropic", "did:web:anthropic.com", "env:CLAUDECODE"},
		{"cursor", []string{"CURSOR_TRACE_ID=abc123"}, "Cursor", "Cursor", "did:web:cursor.com", "env:CURSOR_TRACE_ID"},
		{"windsurf", []string{"WINDSURF_SESSION_ID=xyz"}, "Windsurf", "Codeium", "did:web:codeium.com", "env:WINDSURF_SESSION_ID"},
		{"codex", []string{"CODEX_SANDBOX=seatbelt"}, "Codex", "OpenAI", "did:web:openai.com", "env:CODEX_SANDBOX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unknownComm(t)
			origEnv := environ
			environ = func() []string { return tc.env }
			t.Cleanup(func() { environ = origEnv })

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
		})
	}
}

// A /proc registry hit must win outright — the env scan is skipped even when a
// different host's marker is also present.
func TestDetect_ProcWinsOverEnv(t *testing.T) {
	orig := readComm
	readComm = func(_ int) (string, error) { return "cursor", nil }
	t.Cleanup(func() { readComm = orig })
	origEnv := environ
	environ = func() []string { return []string{"CLAUDECODE=1"} }
	t.Cleanup(func() { environ = origEnv })

	id := Detect()
	if id.Source != "auto:cursor" {
		t.Errorf("Source = %q, want \"auto:cursor\"", id.Source)
	}
	if id.IssuerName != "Cursor" {
		t.Errorf("IssuerName = %q, want \"Cursor\"", id.IssuerName)
	}
}

// When /proc is unreadable, detection still falls through to the env scan.
func TestDetect_ReadCommErrorFallsThroughToEnv(t *testing.T) {
	orig := readComm
	readComm = func(_ int) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { readComm = orig })
	origEnv := environ
	environ = func() []string { return []string{"CODEX_SANDBOX=seatbelt"} }
	t.Cleanup(func() { environ = origEnv })

	id := Detect()
	if id.Source != "env:CODEX_SANDBOX" {
		t.Errorf("Source = %q, want \"env:CODEX_SANDBOX\"", id.Source)
	}
	if id.IssuerName != "Codex" {
		t.Errorf("IssuerName = %q, want \"Codex\"", id.IssuerName)
	}
}

// Markers are checked in declared order, so an earlier host wins when signals
// for several hosts are present at once.
func TestDetect_EnvMarkerPriority(t *testing.T) {
	unknownComm(t)
	origEnv := environ
	environ = func() []string { return []string{"CODEX_SANDBOX=1", "CLAUDECODE=1"} }
	t.Cleanup(func() { environ = origEnv })

	id := Detect()
	if id.Source != "env:CLAUDECODE" {
		t.Errorf("Source = %q, want \"env:CLAUDECODE\"", id.Source)
	}
	if id.IssuerName != "Claude Code" {
		t.Errorf("IssuerName = %q, want \"Claude Code\"", id.IssuerName)
	}
}

// A family marker matching several variables reports a stable Source regardless
// of environment order, because detectEnv sorts before scanning.
func TestDetect_EnvMarkerStableSource(t *testing.T) {
	unknownComm(t)
	origEnv := environ
	// Deliberately unsorted; CODEX_HOME sorts before CODEX_SANDBOX.
	environ = func() []string { return []string{"CODEX_SANDBOX=1", "CODEX_HOME=/x"} }
	t.Cleanup(func() { environ = origEnv })

	id := Detect()
	if id.Source != "env:CODEX_HOME" {
		t.Errorf("Source = %q, want \"env:CODEX_HOME\"", id.Source)
	}
	if id.IssuerName != "Codex" {
		t.Errorf("IssuerName = %q, want \"Codex\"", id.IssuerName)
	}
}

// An exact-name marker must not match a longer variable that merely shares its
// prefix — CLAUDECODE_DEBUG is not the CLAUDECODE signal.
func TestDetect_EnvMarkerExactNoPrefixMatch(t *testing.T) {
	unknownComm(t)
	origEnv := environ
	environ = func() []string { return []string{"CLAUDECODE_DEBUG=1", "CURSOR_TRACE_ID_PARENT=x"} }
	t.Cleanup(func() { environ = origEnv })

	id := Detect()
	if id.Source != "unknown" {
		t.Errorf("Source = %q, want \"unknown\"", id.Source)
	}
	if id.IssuerName != "" {
		t.Errorf("IssuerName = %q, want empty", id.IssuerName)
	}
}

// Every env marker must reference a key present in the registry; a typo would
// otherwise stamp a blank issuer/operator onto receipts.
func TestEnvMarkers_RegistryKeys(t *testing.T) {
	for _, m := range envMarkers {
		if _, ok := registry[m.key]; !ok {
			t.Errorf("envMarker %q references unknown registry key %q", m.name, m.key)
		}
	}
}
