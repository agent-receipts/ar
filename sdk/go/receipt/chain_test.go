package receipt

import (
	"encoding/json"
	"errors"
	"strings"
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
