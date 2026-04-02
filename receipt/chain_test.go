package receipt

import (
	"testing"
)

func buildChain(t *testing.T, kp KeyPair, count int) []AgentReceipt {
	t.Helper()
	chain := make([]AgentReceipt, 0, count)
	var prevHash *string

	for i := 1; i <= count; i++ {
		unsigned := Create(CreateInput{
			Issuer:    Issuer{ID: "did:agent:test"},
			Principal: Principal{ID: "did:user:test"},
			Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
			Outcome:   Outcome{Status: StatusSuccess},
			Chain:     Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
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

func TestVerifyChainValid(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected valid chain, broken at %d", result.BrokenAt)
		for _, r := range result.Receipts {
			t.Logf("  [%d] sig=%v hash=%v seq=%v", r.Index, r.SignatureValid, r.HashLinkValid, r.SequenceValid)
		}
	}
	if result.Length != 5 {
		t.Errorf("expected length 5, got %d", result.Length)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	result := VerifyChain(nil, "")
	if !result.Valid {
		t.Error("empty chain should be valid")
	}
	if result.Length != 0 {
		t.Errorf("expected length 0, got %d", result.Length)
	}
}

func TestVerifyChainSingleReceipt(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 1)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected single-receipt chain to be valid, broken at %d", result.BrokenAt)
	}
	if result.Length != 1 {
		t.Errorf("expected length 1, got %d", result.Length)
	}
	if len(result.Receipts) != 1 {
		t.Errorf("expected 1 receipt result, got %d", len(result.Receipts))
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	// Tamper with second receipt.
	chain[1].CredentialSubject.Action.Type = "hacked"

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected tampered chain to be invalid")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected broken at 1, got %d", result.BrokenAt)
	}
}

func TestVerifyChainDetectsBrokenHashLink(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	// Break hash link on third receipt.
	bad := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	chain[2].CredentialSubject.Chain.PreviousReceiptHash = &bad

	result := VerifyChain(chain, kp.PublicKey)
	if result.Valid {
		t.Error("expected broken hash link to be invalid")
	}
	// Broken at 2 (hash link) but also signature will fail because we modified the receipt.
	if result.BrokenAt != 2 {
		t.Errorf("expected broken at 2, got %d", result.BrokenAt)
	}
}
