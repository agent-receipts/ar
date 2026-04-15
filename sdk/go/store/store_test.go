package store

import (
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func setupStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeSignedReceipt(t *testing.T, kp receipt.KeyPair, seq int, chainID string, prevHash *string) receipt.AgentReceipt {
	t.Helper()
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: seq, PreviousReceiptHash: prevHash, ChainID: chainID},
	})
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestInsertAndGetByID(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)

	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByID(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected receipt, got nil")
	}
	if got.ID != r.ID {
		t.Errorf("expected %s, got %s", r.ID, got.ID)
	}
}

func TestGetByIDNotFound(t *testing.T) {
	s := setupStore(t)
	got, err := s.GetByID("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for missing receipt")
	}
}

func TestGetChain(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, _ := receipt.HashReceipt(r)
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	chain, err := s.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(chain))
	}
	for i, r := range chain {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("expected sequence %d, got %d", i+1, r.CredentialSubject.Chain.Sequence)
		}
	}
}

func TestQueryReceipts(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)
	s.Insert(r, h)

	chainID := "chain-1"
	results, err := s.QueryReceipts(Query{ChainID: &chainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1, got %d", len(results))
	}

	chainID = "nonexistent"
	results, err = s.QueryReceipts(Query{ChainID: &chainID})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0, got %d", len(results))
	}
}

func TestStats(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", nil)
		h, _ := receipt.HashReceipt(r)
		s.Insert(r, h)
	}

	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 3 {
		t.Errorf("expected total 3, got %d", st.Total)
	}
	if st.Chains != 1 {
		t.Errorf("expected 1 chain, got %d", st.Chains)
	}
}

func TestInsertDuplicateReceiptID(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)

	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}
	err := s.Insert(r, h)
	if err == nil {
		t.Fatal("expected error on duplicate receipt ID insert")
	}
}

func TestInsertDuplicateChainSequence(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	r1 := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h1, _ := receipt.HashReceipt(r1)
	if err := s.Insert(r1, h1); err != nil {
		t.Fatal(err)
	}

	// Different receipt (new ID) but same chain_id + sequence.
	r2 := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h2, _ := receipt.HashReceipt(r2)
	err := s.Insert(r2, h2)
	if err == nil {
		t.Fatal("expected error on duplicate chain_id + sequence")
	}
}

func TestQueryReceiptsOrdering(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	// Insert three receipts with timestamps a few seconds apart by
	// stamping them post-Create (Create sets the Action.Timestamp to now).
	timestamps := []string{
		"2024-01-01T00:00:01Z",
		"2024-01-01T00:00:02Z",
		"2024-01-01T00:00:03Z",
	}
	for i, ts := range timestamps {
		unsigned := receipt.Create(receipt.CreateInput{
			Issuer:    receipt.Issuer{ID: "did:agent:test"},
			Principal: receipt.Principal{ID: "did:user:test"},
			Action: receipt.Action{
				Type:      "filesystem.file.read",
				RiskLevel: receipt.RiskLow,
				Timestamp: ts,
			},
			Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:   receipt.Chain{Sequence: i + 1, ChainID: "chain-1"},
		})
		signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			t.Fatal(err)
		}
		h, _ := receipt.HashReceipt(signed)
		if err := s.Insert(signed, h); err != nil {
			t.Fatal(err)
		}
	}

	// Ascending by default.
	asc, err := s.QueryReceipts(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(asc) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(asc))
	}
	if got := asc[0].CredentialSubject.Action.Timestamp; got != timestamps[0] {
		t.Errorf("default ordering: expected oldest %s first, got %s", timestamps[0], got)
	}

	// Newest-first when opted in.
	desc, err := s.QueryReceipts(Query{NewestFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(desc) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(desc))
	}
	if got := desc[0].CredentialSubject.Action.Timestamp; got != timestamps[2] {
		t.Errorf("NewestFirst: expected newest %s first, got %s", timestamps[2], got)
	}
}

func TestQueryReceiptsCombinedFilters(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	// Insert a receipt we can filter on.
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)
	s.Insert(r, h)

	actionType := "filesystem.file.read"
	riskLevel := receipt.RiskLow
	after := "2000-01-01T00:00:00Z"
	before := "2099-01-01T00:00:00Z"

	results, err := s.QueryReceipts(Query{
		ActionType: &actionType,
		RiskLevel:  &riskLevel,
		After:      &after,
		Before:     &before,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result with combined filters, got %d", len(results))
	}
}

func TestCloseMultipleTimes(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	// Second close should not panic.
	_ = s.Close()
}

func TestVerifyStoredChain(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, _ := receipt.HashReceipt(r)
		s.Insert(r, h)
		prevHash = &h
	}

	result, err := s.VerifyStoredChain("chain-1", kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Errorf("expected valid chain, broken at %d", result.BrokenAt)
	}
}
