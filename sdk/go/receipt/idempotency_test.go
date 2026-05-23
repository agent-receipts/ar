package receipt

import (
	"strings"
	"testing"
)

// buildChainWithKeys builds a signed, hash-linked chain whose i-th receipt
// carries idempotencyKeys[i] on action.idempotency_key (empty = omitted).
func buildChainWithKeys(t *testing.T, kp KeyPair, idempotencyKeys []string) []AgentReceipt {
	t.Helper()
	chain := make([]AgentReceipt, 0, len(idempotencyKeys))
	var prevHash *string
	for i, key := range idempotencyKeys {
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action: Action{
				Type:           "filesystem.file.read",
				RiskLevel:      RiskLow,
				IdempotencyKey: key,
			},
			Outcome: Outcome{Status: StatusSuccess},
			Chain:   Chain{Sequence: i + 1, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		})
		signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
		h, err := HashReceipt(signed)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	return chain
}

func TestCreateStampsIdempotencyKey(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow, IdempotencyKey: "req-1"},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	if r.CredentialSubject.Action.IdempotencyKey != "req-1" {
		t.Errorf("idempotency_key = %q, want %q", r.CredentialSubject.Action.IdempotencyKey, "req-1")
	}
}

// TestIdempotencyKeyOmittedWhenEmpty pins that an empty key serialises to an
// absent field (omitempty), so receipts that do not set it never carry it.
func TestIdempotencyKeyOmittedWhenEmpty(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	canonical, err := Canonicalize(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(canonical, "idempotency_key") {
		t.Errorf("canonical form should omit idempotency_key when empty: %s", canonical)
	}
}

// TestVerifyChainDuplicateIdempotencyKeyWarning verifies that a duplicate
// idempotency_key surfaces as a warning, not a failure (spec §7.3.6).
func TestVerifyChainDuplicateIdempotencyKeyWarning(t *testing.T) {
	kp, _ := GenerateKeyPair()
	// Receipts 0 and 2 share "req-A"; receipt 1 has a distinct key.
	chain := buildChainWithKeys(t, kp, []string{"req-A", "req-B", "req-A"})

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Fatalf("duplicate idempotency_key must not invalidate the chain; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %d: %v", len(result.Warnings), result.Warnings)
	}
	w := result.Warnings[0]
	if !strings.Contains(w, "req-A") || !strings.Contains(w, "0") || !strings.Contains(w, "2") {
		t.Errorf("warning should name key req-A and indices 0, 2; got %q", w)
	}
}

// TestVerifyChainNoDuplicateNoWarning confirms that distinct (or absent) keys
// produce no warnings.
func TestVerifyChainNoDuplicateNoWarning(t *testing.T) {
	kp, _ := GenerateKeyPair()
	cases := map[string][]string{
		"all distinct": {"req-1", "req-2", "req-3"},
		"all absent":   {"", "", ""},
		"mixed absent": {"req-1", "", "req-2"},
	}
	for name, keys := range cases {
		t.Run(name, func(t *testing.T) {
			chain := buildChainWithKeys(t, kp, keys)
			result := VerifyChain(chain, kp.PublicKey)
			if !result.Valid {
				t.Fatalf("chain should be valid, broken at %d", result.BrokenAt)
			}
			if len(result.Warnings) != 0 {
				t.Errorf("expected no warnings, got %v", result.Warnings)
			}
		})
	}
}

// TestVerifyChainEmptyKeyNeverWarns pins that repeated *empty* keys (i.e.
// absent fields) are never treated as duplicates.
func TestVerifyChainEmptyKeyNeverWarns(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithKeys(t, kp, []string{"", "", "", ""})
	result := VerifyChain(chain, kp.PublicKey)
	if len(result.Warnings) != 0 {
		t.Errorf("absent idempotency keys must never warn, got %v", result.Warnings)
	}
}
