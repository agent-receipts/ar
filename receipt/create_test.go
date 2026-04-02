package receipt

import (
	"strings"
	"testing"
)

func TestCreateSetsDefaults(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if !strings.HasPrefix(r.ID, "urn:receipt:") {
		t.Errorf("expected urn:receipt: prefix, got %s", r.ID)
	}
	if !strings.HasPrefix(r.CredentialSubject.Action.ID, "act_") {
		t.Errorf("expected act_ prefix, got %s", r.CredentialSubject.Action.ID)
	}
	if r.IssuanceDate == "" {
		t.Error("expected issuance date to be set")
	}
	if r.CredentialSubject.Action.Timestamp == "" {
		t.Error("expected action timestamp to be set")
	}
	if r.Version != Version {
		t.Errorf("expected version %s, got %s", Version, r.Version)
	}
	if len(r.Context) != 2 {
		t.Errorf("expected 2 context entries, got %d", len(r.Context))
	}
	if len(r.Type) != 2 {
		t.Errorf("expected 2 type entries, got %d", len(r.Type))
	}
}

func TestCreateWithZeroValueInputs(t *testing.T) {
	// Empty Issuer.ID and empty Action.Type should not panic.
	r := Create(CreateInput{
		Issuer:    Issuer{ID: ""},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if r.ID == "" {
		t.Error("expected receipt ID to be generated")
	}
	if r.IssuanceDate == "" {
		t.Error("expected issuance date to be set")
	}
}

func TestCreatePreservesExplicitActionID(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{ID: "act_custom", Type: "unknown", RiskLevel: RiskMedium, Timestamp: "2024-01-01T00:00:00Z"},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if r.CredentialSubject.Action.ID != "act_custom" {
		t.Errorf("expected act_custom, got %s", r.CredentialSubject.Action.ID)
	}
	if r.CredentialSubject.Action.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("expected explicit timestamp, got %s", r.CredentialSubject.Action.Timestamp)
	}
}

func TestCreateWithOptionalFields(t *testing.T) {
	truncated := true
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
		Intent:    &Intent{PromptPreview: "do the thing", PromptPreviewTruncated: &truncated},
		Authorization: &Authorization{
			Scopes:    []string{"read", "write"},
			GrantedAt: "2024-01-01T00:00:00Z",
		},
	})

	if r.CredentialSubject.Intent == nil {
		t.Fatal("expected intent to be set")
	}
	if r.CredentialSubject.Intent.PromptPreview != "do the thing" {
		t.Errorf("unexpected prompt preview: %s", r.CredentialSubject.Intent.PromptPreview)
	}
	if r.CredentialSubject.Authorization == nil {
		t.Fatal("expected authorization to be set")
	}
	if len(r.CredentialSubject.Authorization.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(r.CredentialSubject.Authorization.Scopes))
	}
}
