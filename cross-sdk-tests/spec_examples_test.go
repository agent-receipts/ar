//go:build integration

package crosssdk_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// specReceipt is a loose representation of a spec example receipt.
// Uses validFrom (spec convention) rather than issuanceDate (SDK convention).
type specReceipt struct {
	Context           []string              `json:"@context"`
	ID                string                `json:"id"`
	Type              []string              `json:"type"`
	Version           string                `json:"version"`
	Issuer            map[string]any        `json:"issuer"`
	ValidFrom         string                `json:"validFrom"`
	CredentialSubject specCredentialSubject `json:"credentialSubject"`
	Proof             map[string]any        `json:"proof"`
}

type specCredentialSubject struct {
	Principal map[string]any `json:"principal"`
	Action    map[string]any `json:"action"`
	Outcome   map[string]any `json:"outcome"`
	Chain     specChain      `json:"chain"`
}

type specChain struct {
	Sequence            int     `json:"sequence"`
	PreviousReceiptHash *string `json:"previous_receipt_hash"`
	ChainID             string  `json:"chain_id"`
}

func loadSpecExample(t *testing.T, name string) specReceipt {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "examples", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var r specReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return r
}

// TestSpecExamplesHaveRequiredFields validates that all spec example receipts
// contain the required top-level fields.
func TestSpecExamplesHaveRequiredFields(t *testing.T) {
	examples := []string{
		"minimal-receipt.json",
		"full-receipt.json",
		"chain-receipt-1.json",
		"chain-receipt-2.json",
		"chain-receipt-3.json",
		"delegation-receipt.json",
	}

	for _, name := range examples {
		t.Run(name, func(t *testing.T) {
			r := loadSpecExample(t, name)

			if len(r.Context) != 2 {
				t.Errorf("expected 2 context entries, got %d", len(r.Context))
			}
			if r.Context[0] != "https://www.w3.org/ns/credentials/v2" {
				t.Errorf("first context should be W3C VC v2, got %s", r.Context[0])
			}

			if r.ID == "" {
				t.Error("missing id")
			}

			if len(r.Type) != 2 || r.Type[0] != "VerifiableCredential" || r.Type[1] != "AgentReceipt" {
				t.Errorf("unexpected type: %v", r.Type)
			}

			if r.Version != "0.1.0" {
				t.Errorf("unexpected version: %s", r.Version)
			}

			if r.Issuer["id"] == nil || r.Issuer["id"] == "" {
				t.Error("missing issuer.id")
			}

			if r.ValidFrom == "" {
				t.Error("missing validFrom")
			}

			if r.CredentialSubject.Principal["id"] == nil {
				t.Error("missing principal.id")
			}

			action := r.CredentialSubject.Action
			for _, field := range []string{"id", "type", "risk_level", "timestamp"} {
				if action[field] == nil || action[field] == "" {
					t.Errorf("missing action.%s", field)
				}
			}

			if r.CredentialSubject.Outcome["status"] == nil {
				t.Error("missing outcome.status")
			}

			if r.CredentialSubject.Chain.ChainID == "" {
				t.Error("missing chain.chain_id")
			}

			if r.Proof == nil {
				t.Error("missing proof")
			}
			if r.Proof["type"] != "Ed25519Signature2020" {
				t.Errorf("unexpected proof type: %v", r.Proof["type"])
			}
		})
	}
}

// TestSpecChainExamplesSequence validates that the chain example receipts
// have correct sequence ordering and hash linkage structure.
func TestSpecChainExamplesSequence(t *testing.T) {
	chain := []specReceipt{
		loadSpecExample(t, "chain-receipt-1.json"),
		loadSpecExample(t, "chain-receipt-2.json"),
		loadSpecExample(t, "chain-receipt-3.json"),
	}

	// All should share the same chain_id.
	chainID := chain[0].CredentialSubject.Chain.ChainID
	for i, r := range chain {
		if r.CredentialSubject.Chain.ChainID != chainID {
			t.Errorf("receipt %d has chain_id %q, expected %q", i+1, r.CredentialSubject.Chain.ChainID, chainID)
		}
	}

	// Verify sequence numbers are 1, 2, 3.
	for i, r := range chain {
		expected := i + 1
		if r.CredentialSubject.Chain.Sequence != expected {
			t.Errorf("receipt %d: expected sequence %d, got %d", i+1, expected, r.CredentialSubject.Chain.Sequence)
		}
	}

	// First receipt must have null previous_receipt_hash.
	if chain[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Error("first receipt should have null previous_receipt_hash")
	}

	// Subsequent receipts must have non-null previous_receipt_hash.
	for i := 1; i < len(chain); i++ {
		if chain[i].CredentialSubject.Chain.PreviousReceiptHash == nil {
			t.Errorf("receipt %d should have non-null previous_receipt_hash", i+1)
		}
	}

	// Risk levels should escalate: low -> medium -> high.
	expectedRiskLevels := []string{"low", "medium", "high"}
	for i, r := range chain {
		risk, _ := r.CredentialSubject.Action["risk_level"].(string)
		if risk != expectedRiskLevels[i] {
			t.Errorf("receipt %d: expected risk %s, got %s", i+1, expectedRiskLevels[i], risk)
		}
	}
}

// TestSpecExamplesIssuerConsistency verifies that chain examples share
// the same issuer.
func TestSpecExamplesIssuerConsistency(t *testing.T) {
	chain := []specReceipt{
		loadSpecExample(t, "chain-receipt-1.json"),
		loadSpecExample(t, "chain-receipt-2.json"),
		loadSpecExample(t, "chain-receipt-3.json"),
	}

	issuerID := chain[0].Issuer["id"]
	for i, r := range chain[1:] {
		if r.Issuer["id"] != issuerID {
			t.Errorf("receipt %d has different issuer: %v vs %v", i+2, r.Issuer["id"], issuerID)
		}
	}
}
