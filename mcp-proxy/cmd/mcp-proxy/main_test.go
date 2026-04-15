package main

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

func TestBuildApprovalDeniedMessageTimeout(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalTimedOut, 15*time.Second)

	for _, want := range []string{
		"timed out after 15s",
		"tool=create_pull_request",
		"rule=pause_high_risk",
		"risk=70",
		"approval_id=abc123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q to contain %q", got, want)
		}
	}
}

func TestBuildApprovalDeniedMessageExplicitDeny(t *testing.T) {
	got := buildApprovalDeniedMessage("create_pull_request", "pause_high_risk", 70, "abc123", audit.ApprovalDenied, 15*time.Second)

	if !strings.Contains(got, "denied by approval workflow") {
		t.Fatalf("expected explicit deny message, got %q", got)
	}
	if strings.Contains(got, "timed out") {
		t.Fatalf("explicit deny message should not mention timeout: %q", got)
	}
}
