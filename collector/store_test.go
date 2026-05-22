package collector

import (
	"errors"
	"sync"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// testReceipt constructs a minimal AgentReceipt for store tests. It is not a
// schema-valid receipt for the wire — the collector store does not validate
// structure, so this is sufficient.
func testReceipt(id string) receipt.AgentReceipt {
	return receipt.AgentReceipt{
		ID:           id,
		IssuanceDate: "2026-05-22T00:00:00Z",
		Issuer:       receipt.Issuer{ID: "did:example:test"},
		CredentialSubject: receipt.CredentialSubject{
			Principal: receipt.Principal{ID: "did:example:user"},
			Action: receipt.Action{
				Type:      "tool_call",
				RiskLevel: receipt.RiskLow,
				Timestamp: "2026-05-22T00:00:00Z",
			},
			Outcome: receipt.Outcome{Status: "success"},
			Chain:   receipt.Chain{ChainID: "chain-1", Sequence: 0},
		},
	}
}

func TestInMemoryStore_InsertAndExists(t *testing.T) {
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:1")

	if exists, err := s.Exists(r.ID); err != nil || exists {
		t.Fatalf("Exists before insert: exists=%v err=%v, want false/nil", exists, err)
	}

	if err := s.Insert(r, "sha256:deadbeef"); err != nil {
		t.Fatalf("Insert: unexpected error: %v", err)
	}

	if exists, err := s.Exists(r.ID); err != nil || !exists {
		t.Fatalf("Exists after insert: exists=%v err=%v, want true/nil", exists, err)
	}

	if s.Len() != 1 {
		t.Fatalf("Len after insert: %d, want 1", s.Len())
	}
}

func TestInMemoryStore_InsertDuplicate(t *testing.T) {
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:dup")

	if err := s.Insert(r, "sha256:1"); err != nil {
		t.Fatalf("first Insert: %v", err)
	}

	err := s.Insert(r, "sha256:2")
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Insert: err=%v, want ErrDuplicate", err)
	}

	// The first insert's data must not be overwritten.
	_, hash, ok := s.Get(r.ID)
	if !ok || hash != "sha256:1" {
		t.Fatalf("Get after duplicate Insert: hash=%q ok=%v, want sha256:1/true", hash, ok)
	}
}

func TestInMemoryStore_ConcurrentInserts(t *testing.T) {
	// Two concurrent inserts of the same id: exactly one must succeed, the
	// other must observe ErrDuplicate. This is the contract HttpEmitter
	// retries rely on — safe re-delivery cannot create silent duplicates.
	s := NewInMemoryStore()
	r := testReceipt("urn:receipt:race")

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.Insert(r, "sha256:r")
		}(i)
	}
	wg.Wait()

	var ok, dup int
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrDuplicate):
			dup++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || dup != 1 {
		t.Fatalf("concurrent inserts: ok=%d dup=%d, want 1/1", ok, dup)
	}
}

func TestInMemoryStore_ExistsUnknown(t *testing.T) {
	s := NewInMemoryStore()
	if exists, err := s.Exists("urn:receipt:nope"); err != nil || exists {
		t.Fatalf("Exists for unknown id: exists=%v err=%v, want false/nil", exists, err)
	}
}
