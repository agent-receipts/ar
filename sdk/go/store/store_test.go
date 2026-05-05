package store

import (
	"path/filepath"
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

func TestGetChainTail_Empty(t *testing.T) {
	s := setupStore(t)
	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("expected found=false for empty chain")
	}
	if seq != 0 || hash != "" {
		t.Errorf("expected zero values, got seq=%d hash=%q", seq, hash)
	}
}

func TestGetChainTail_SingleRow(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}

	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if seq != 1 {
		t.Errorf("expected seq=1, got %d", seq)
	}
	if hash != h {
		t.Errorf("expected hash=%s, got %s", h, hash)
	}
}

func TestGetChainTail_HighestSequence(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	// Insert 1..5 in non-monotonic order to confirm the query orders by sequence,
	// not insertion order.
	insertOrder := []int{3, 1, 5, 2, 4}
	hashes := make(map[int]string, len(insertOrder))
	for _, seq := range insertOrder {
		r := makeSignedReceipt(t, kp, seq, "chain-1", nil)
		h, _ := receipt.HashReceipt(r)
		if err := s.Insert(r, h); err != nil {
			t.Fatalf("insert seq=%d: %v", seq, err)
		}
		hashes[seq] = h
	}

	seq, hash, found, err := s.GetChainTail("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if seq != 5 {
		t.Errorf("expected seq=5 (highest), got %d", seq)
	}
	if hash != hashes[5] {
		t.Errorf("expected hash for seq=5, got hash for a different row")
	}
}

func TestGetChainTail_MultiChainIsolation(t *testing.T) {
	s := setupStore(t)
	kp, _ := receipt.GenerateKeyPair()

	rA := makeSignedReceipt(t, kp, 7, "chain-A", nil)
	hA, _ := receipt.HashReceipt(rA)
	if err := s.Insert(rA, hA); err != nil {
		t.Fatal(err)
	}
	rB := makeSignedReceipt(t, kp, 2, "chain-B", nil)
	hB, _ := receipt.HashReceipt(rB)
	if err := s.Insert(rB, hB); err != nil {
		t.Fatal(err)
	}

	seqA, hashA, foundA, err := s.GetChainTail("chain-A")
	if err != nil || !foundA {
		t.Fatalf("chain-A: err=%v found=%v", err, foundA)
	}
	if seqA != 7 || hashA != hA {
		t.Errorf("chain-A leaked: seq=%d hash=%s", seqA, hashA)
	}

	seqB, hashB, foundB, err := s.GetChainTail("chain-B")
	if err != nil || !foundB {
		t.Fatalf("chain-B: err=%v found=%v", err, foundB)
	}
	if seqB != 2 || hashB != hB {
		t.Errorf("chain-B leaked: seq=%d hash=%s", seqB, hashB)
	}

	_, _, foundC, err := s.GetChainTail("chain-C")
	if err != nil {
		t.Fatal(err)
	}
	if foundC {
		t.Error("chain-C should be empty")
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

func TestMaxRowIDEmpty(t *testing.T) {
	s := setupStore(t)
	max, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}
	if max != 0 {
		t.Errorf("expected 0 for empty store, got %d", max)
	}
}

func TestMaxRowIDAfterInsert(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	max, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}
	if max != 3 {
		t.Errorf("expected rowid 3 after 3 inserts, got %d", max)
	}
}

func TestQueryAfterRowIDReturnsOnlyNewRows(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 2; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	watermark, err := s.MaxRowID()
	if err != nil {
		t.Fatal(err)
	}

	// Insert two more after the watermark.
	for i := 3; i <= 4; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	results, newMax, err := s.QueryAfterRowID(Query{}, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 new rows, got %d", len(results))
	}
	if newMax != 4 {
		t.Errorf("expected newMax rowid 4, got %d", newMax)
	}
	// Second call with the advanced watermark should return nothing and
	// leave the watermark unchanged.
	results, same, err := s.QueryAfterRowID(Query{}, newMax)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 rows after advancing watermark, got %d", len(results))
	}
	if same != newMax {
		t.Errorf("expected watermark to stay at %d, got %d", newMax, same)
	}
}

func TestQueryReceiptsWithWatermarkReturnsConsistentPair(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	receipts, watermark, err := s.QueryReceiptsWithWatermark(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(receipts))
	}
	if watermark != 3 {
		t.Errorf("expected watermark 3, got %d", watermark)
	}

	// Insert another row and confirm the watermark from above makes
	// QueryAfterRowID return only the new row.
	r := makeSignedReceipt(t, kp, 4, "chain-1", prevHash)
	h, err := receipt.HashReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(r, h); err != nil {
		t.Fatal(err)
	}
	newRows, _, err := s.QueryAfterRowID(Query{}, watermark)
	if err != nil {
		t.Fatal(err)
	}
	if len(newRows) != 1 {
		t.Errorf("expected 1 new row after watermark, got %d", len(newRows))
	}
}

func TestQueryAfterRowIDAppliesFilters(t *testing.T) {
	s := setupStore(t)
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Insert into two different chains.
	for i, chain := range []string{"chain-a", "chain-b"} {
		r := makeSignedReceipt(t, kp, i+1, chain, nil)
		h, err := receipt.HashReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Insert(r, h); err != nil {
			t.Fatal(err)
		}
	}

	chainA := "chain-a"
	results, _, err := s.QueryAfterRowID(Query{ChainID: &chainA}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for chain-a filter, got %d", len(results))
	}
	if results[0].CredentialSubject.Chain.ChainID != chainA {
		t.Errorf("wrong chain: %s", results[0].CredentialSubject.Chain.ChainID)
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

func TestOpenReadOnlyVerifiesExistingChain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := receipt.GenerateKeyPair()
	var prevHash *string
	for i := 1; i <= 3; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, _ := receipt.HashReceipt(r)
		if err := rw.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	t.Cleanup(func() { ro.Close() })

	result, err := ro.VerifyStoredChain("chain-1", kp.PublicKey)
	if err != nil {
		t.Fatalf("VerifyStoredChain on read-only handle: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain, broken at %d", result.BrokenAt)
	}
	if result.Length != 3 {
		t.Fatalf("expected 3 receipts verified, got %d", result.Length)
	}
}

func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })

	kp, _ := receipt.GenerateKeyPair()
	r := makeSignedReceipt(t, kp, 1, "chain-1", nil)
	h, _ := receipt.HashReceipt(r)
	// We deliberately don't pin a specific SQLite error string here — the
	// driver's wording around read-only rejection has shifted between
	// modernc.org/sqlite versions, and the behaviour we actually care about
	// is "the write was rejected", regardless of how it's phrased.
	if err := ro.Insert(r, h); err == nil {
		t.Fatal("expected Insert against read-only handle to fail, got nil")
	}
}

func TestOpenReadOnlyConcurrentWithWriter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "receipts.db")

	rw, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rw.Close() })

	kp, _ := receipt.GenerateKeyPair()
	var prevHash *string
	for i := 1; i <= 2; i++ {
		r := makeSignedReceipt(t, kp, i, "chain-1", prevHash)
		h, _ := receipt.HashReceipt(r)
		if err := rw.Insert(r, h); err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}

	// Open read-only while the writer handle is still live — verifies the
	// daemon-up case where agent-receipts verify must not collide with the
	// daemon's exclusive ownership of the write side.
	ro, err := OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("OpenReadOnly while writer is open: %v", err)
	}
	t.Cleanup(func() { ro.Close() })

	got, err := ro.GetChain("chain-1")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(got))
	}
}

func TestOpenReadOnlyRejectsMemoryAndEmpty(t *testing.T) {
	if _, err := OpenReadOnly(""); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := OpenReadOnly(":memory:"); err == nil {
		t.Fatal("expected error for :memory:")
	}
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
