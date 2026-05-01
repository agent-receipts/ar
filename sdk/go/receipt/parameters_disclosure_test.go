package receipt

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestParametersDisclosureRoundTrip verifies that the optional
// parameters_disclosure map (ADR-0012) survives JSON marshal/unmarshal,
// is included in the canonical JSON form, and therefore contributes to
// the receipt hash.
func TestParametersDisclosureRoundTrip(t *testing.T) {
	disclosure := map[string]string{
		"path":   "/etc/hosts",
		"flags":  "ro",
		"reason": "diagnostic read",
	}

	action := Action{
		ID:                   "act_test",
		Type:                 "filesystem.file.read",
		RiskLevel:            RiskLow,
		ParametersHash:       "sha256:deadbeef",
		ParametersDisclosure: disclosure,
		Timestamp:            "2026-04-28T00:00:00Z",
	}

	// Marshal the Action and confirm parameters_disclosure is present.
	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal action: %v", err)
	}
	if !strings.Contains(string(encoded), `"parameters_disclosure"`) {
		t.Fatalf("expected parameters_disclosure in encoded JSON, got %s", encoded)
	}

	// Unmarshal and ensure the field round-trips with all entries intact.
	var decoded Action
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal action: %v", err)
	}
	if len(decoded.ParametersDisclosure) != len(disclosure) {
		t.Fatalf("expected %d disclosure entries, got %d",
			len(disclosure), len(decoded.ParametersDisclosure))
	}
	for k, v := range disclosure {
		if got := decoded.ParametersDisclosure[k]; got != v {
			t.Errorf("disclosure[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestParametersDisclosureOmitEmpty verifies the field is omitted from
// JSON when nil or empty (omitempty), so existing receipts without
// disclosure data continue to canonicalize identically.
func TestParametersDisclosureOmitEmpty(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]string
	}{
		{name: "nil_map", m: nil},
		{name: "empty_map", m: map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := Action{
				ID:                   "act_test",
				Type:                 "filesystem.file.read",
				RiskLevel:            RiskLow,
				ParametersDisclosure: tt.m,
				Timestamp:            "2026-04-28T00:00:00Z",
			}
			encoded, err := json.Marshal(action)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(encoded), "parameters_disclosure") {
				t.Errorf("expected parameters_disclosure to be omitted, got %s", encoded)
			}
		})
	}
}

// TestParametersDisclosureCanonicalIncluded verifies the field is
// included in the RFC 8785 canonical form (object keys sorted by UTF-16
// code units), and that removing it changes the receipt hash.
func TestParametersDisclosureCanonicalIncluded(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	withDisclosure := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action: Action{
			ID:                   "act_fixed",
			Type:                 "filesystem.file.read",
			RiskLevel:            RiskLow,
			Timestamp:            "2026-04-28T00:00:00Z",
			ParametersDisclosure: map[string]string{"path": "/etc/hosts"},
		},
		Outcome: Outcome{Status: StatusSuccess},
		Chain:   Chain{Sequence: 1, ChainID: "chain-1"},
	})
	withDisclosure.ID = "urn:receipt:fixed"
	withDisclosure.IssuanceDate = "2026-04-28T00:00:00Z"

	withoutDisclosure := withDisclosure
	subjectCopy := withDisclosure.CredentialSubject
	actionCopy := subjectCopy.Action
	actionCopy.ParametersDisclosure = nil
	subjectCopy.Action = actionCopy
	withoutDisclosure.CredentialSubject = subjectCopy

	canonWith, err := Canonicalize(withDisclosure)
	if err != nil {
		t.Fatalf("canonicalize with: %v", err)
	}
	if !strings.Contains(canonWith, `"parameters_disclosure":{"path":"/etc/hosts"}`) {
		t.Errorf("canonical form missing parameters_disclosure: %s", canonWith)
	}

	canonWithout, err := Canonicalize(withoutDisclosure)
	if err != nil {
		t.Fatalf("canonicalize without: %v", err)
	}
	if canonWith == canonWithout {
		t.Error("expected canonical forms to differ when disclosure is removed")
	}

	// Sign and hash both — the receipt hash must reflect the disclosure.
	signedWith, err := Sign(withDisclosure, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	signedWithout, err := Sign(withoutDisclosure, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	hashWith, err := HashReceipt(signedWith)
	if err != nil {
		t.Fatal(err)
	}
	hashWithout, err := HashReceipt(signedWithout)
	if err != nil {
		t.Fatal(err)
	}
	if hashWith == hashWithout {
		t.Error("expected receipt hashes to differ when disclosure is removed")
	}
}
