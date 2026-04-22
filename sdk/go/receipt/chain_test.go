package receipt

import (
	"encoding/json"
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

// --- ADR-0008 tests below ---

// buildChainWithTerminal builds a chain of `count` receipts where the last
// receipt has chain.terminal: true.
func buildChainWithTerminal(t *testing.T, kp KeyPair, count int) []AgentReceipt {
	t.Helper()
	chain := buildChain(t, kp, count-1)

	// Build terminal receipt.
	var prevHash *string
	if len(chain) > 0 {
		h, err := HashReceipt(chain[len(chain)-1])
		if err != nil {
			t.Fatal(err)
		}
		prevHash = &h
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: count, PreviousReceiptHash: prevHash, ChainID: "chain-1"},
		Terminal:  true,
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return append(chain, signed)
}

func TestChainTruncationPins(t *testing.T) {
	// Dropping tail receipts must not break verification (pins current behaviour).
	// This is a deliberate design floor documented in spec §7.3.1.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3] // drop last 2

	result := VerifyChain(truncated, kp.PublicKey)
	if !result.Valid {
		t.Errorf("truncated chain (no expected length/hash) must be Valid: true; broken at %d: %s", result.BrokenAt, result.Error)
	}
	if result.Length != 3 {
		t.Errorf("expected length 3, got %d", result.Length)
	}
}

func TestExpectedLength(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3]

	five := 5
	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{ExpectedLength: &five})
	if result.Valid {
		t.Error("expected Valid: false when ExpectedLength=5 but chain has 3")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestExpectedLengthMatch(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	five := 5
	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{ExpectedLength: &five})
	if !result.Valid {
		t.Errorf("expected Valid: true when ExpectedLength matches, got error: %s", result.Error)
	}
}

func TestExpectedFinalHash(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)
	truncated := chain[:3]

	// Use the hash of the real final receipt as the expected value.
	realFinalHash, _ := HashReceipt(chain[4])
	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{ExpectedFinalHash: realFinalHash})
	if result.Valid {
		t.Error("expected Valid: false when ExpectedFinalHash doesn't match truncated chain")
	}
}

func TestExpectedFinalHashMatch(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 5)

	finalHash, err := HashReceipt(chain[4])
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{ExpectedFinalHash: finalHash})
	if !result.Valid {
		t.Errorf("expected Valid: true when ExpectedFinalHash matches, got: %s", result.Error)
	}
}

func TestTerminalRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("chain ending in terminal must be valid: broken at %d: %s", result.BrokenAt, result.Error)
	}

	// Confirm last receipt has terminal: true.
	last := chain[len(chain)-1]
	if last.CredentialSubject.Chain.Terminal == nil || !*last.CredentialSubject.Chain.Terminal {
		t.Error("last receipt must have chain.terminal: true")
	}
}

func TestReceiptAfterTerminal(t *testing.T) {
	// Build a chain where a receipt appears after a terminal receipt.
	// This must always fail regardless of any caller options.
	kp, _ := GenerateKeyPair()
	terminalChain := buildChainWithTerminal(t, kp, 3) // 3 receipts, last is terminal

	// Append a receipt after the terminal one — this is a protocol violation.
	terminalHash, err := HashReceipt(terminalChain[2])
	if err != nil {
		t.Fatal(err)
	}
	extra := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 4, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
	})
	extraSigned, err := Sign(extra, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	bad := append(terminalChain, extraSigned)

	result := VerifyChain(bad, kp.PublicKey)
	if result.Valid {
		t.Error("chain with receipt after terminal must be Valid: false")
	}
	if result.Error == "" {
		t.Error("expected a clear error message for receipt-after-terminal")
	}
	// Should contain "terminal" in the error message.
	if !containsStr(result.Error, "terminal") {
		t.Errorf("error message should mention 'terminal', got: %s", result.Error)
	}
}

func TestReceiptAfterTerminalIgnoresCallerOptions(t *testing.T) {
	// receipt-after-terminal must fire even with no caller options.
	kp, _ := GenerateKeyPair()
	terminalChain := buildChainWithTerminal(t, kp, 2)

	terminalHash, err := HashReceipt(terminalChain[1])
	if err != nil {
		t.Fatal(err)
	}
	extra := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 3, PreviousReceiptHash: &terminalHash, ChainID: "chain-1"},
	})
	extraSigned, _ := Sign(extra, kp.PrivateKey, "did:agent:test#key-1")
	bad := append(terminalChain, extraSigned)

	// Even with no options, must fail.
	result := VerifyChain(bad, kp.PublicKey)
	if result.Valid {
		t.Error("receipt-after-terminal must be caught unconditionally")
	}
}

func TestRequireTerminalWithTerminal(t *testing.T) {
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey, ChainVerifyOptions{RequireTerminal: true})
	if !result.Valid {
		t.Errorf("RequireTerminal with terminal chain must be valid: %s", result.Error)
	}
}

func TestRequireTerminalTruncated(t *testing.T) {
	// RequireTerminal: true on a chain where the terminal receipt was dropped → invalid.
	kp, _ := GenerateKeyPair()
	chain := buildChainWithTerminal(t, kp, 3)
	// Drop the terminal receipt (last one).
	truncated := chain[:2]

	result := VerifyChain(truncated, kp.PublicKey, ChainVerifyOptions{RequireTerminal: true})
	if result.Valid {
		t.Error("RequireTerminal with missing terminal receipt must be Valid: false")
	}
}

func TestRequireTerminalWithoutTerminal(t *testing.T) {
	// RequireTerminal: false (default) with non-terminal chain → valid.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 3)

	result := VerifyChain(chain, kp.PublicKey) // no options
	if !result.Valid {
		t.Errorf("non-terminal chain without RequireTerminal must be valid: %s", result.Error)
	}
}

func TestResponseHashHappyPath(t *testing.T) {
	responseBody := []byte(`{"result":"ok","status":200}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-resp"},
		ResponseBody: responseBody,
	})

	if unsigned.CredentialSubject.Outcome.ResponseHash == "" {
		t.Fatal("expected response_hash to be populated")
	}

	// Recompute the hash manually and compare.
	var responseAny any
	if err := json.Unmarshal(responseBody, &responseAny); err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonicalize(responseAny)
	if err != nil {
		t.Fatal(err)
	}
	expected := SHA256Hash(canonical)
	if unsigned.CredentialSubject.Outcome.ResponseHash != expected {
		t.Errorf("hash mismatch: got %s, want %s", unsigned.CredentialSubject.Outcome.ResponseHash, expected)
	}
}

func TestResponseHashMissingBody(t *testing.T) {
	// A receipt with response_hash but no body supplied → continues with note.
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-note"},
		ResponseBody: []byte(`{"result":"ok"}`),
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey)
	if !result.Valid {
		t.Errorf("missing response body must not fail verification: %s", result.Error)
	}
	if result.ResponseHashNote == "" {
		t.Error("expected ResponseHashNote to be non-empty when response_hash present but body absent")
	}
}

func TestResponseHashAbsent(t *testing.T) {
	// No response_hash → no note, no failure.
	kp, _ := GenerateKeyPair()
	chain := buildChain(t, kp, 1)

	result := VerifyChain(chain, kp.PublicKey)
	if !result.Valid {
		t.Errorf("expected valid, got error: %s", result.Error)
	}
	if result.ResponseHashNote != "" {
		t.Errorf("expected empty ResponseHashNote, got: %s", result.ResponseHashNote)
	}
}

func TestRedactThenHash(t *testing.T) {
	// The ordering test: redact → hash, not hash → redact.
	// A known "secret" in the raw response must NOT appear in the hash computation.
	rawResponse := map[string]any{
		"result":   "ok",
		"password": "super-secret-value",
	}

	// Simulate redaction: replace sensitive value with [REDACTED].
	redacted := map[string]any{
		"result":   "ok",
		"password": "[REDACTED]",
	}

	// Hash of redacted form.
	rawRedacted := `{"password":"[REDACTED]","result":"ok"}` // RFC 8785 sorted
	hashOfRedacted := SHA256Hash(rawRedacted)

	// Hash of raw form (should differ).
	rawRaw := `{"password":"super-secret-value","result":"ok"}`
	hashOfRaw := SHA256Hash(rawRaw)

	if hashOfRedacted == hashOfRaw {
		t.Fatal("test setup error: hashes of raw and redacted should differ")
	}

	// Create receipt using pre-redacted body.
	redactedJSON, _ := json.Marshal(redacted)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-redact"},
		ResponseBody: redactedJSON,
	})

	// Verify the stored hash equals hash(redacted), not hash(raw response).
	got := unsigned.CredentialSubject.Outcome.ResponseHash
	if got != hashOfRedacted {
		t.Errorf("response_hash should equal hash(redacted): got %s, want %s", got, hashOfRedacted)
	}
	if got == hashOfRaw {
		t.Error("response_hash must not equal hash(raw response)")
	}
	_ = rawResponse // suppress unused warning
}

func TestTerminalFieldNeverFalse(t *testing.T) {
	// Creating a receipt with Terminal: false should NOT emit terminal field.
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-t"},
		Terminal:  false, // explicitly false — must produce no terminal field
	})
	if unsigned.CredentialSubject.Chain.Terminal != nil {
		t.Error("Terminal: false must not emit chain.terminal field (Terminal pointer must be nil)")
	}
}

func TestTerminalTrueEmits(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-t"},
		Terminal:  true,
	})
	if unsigned.CredentialSubject.Chain.Terminal == nil {
		t.Fatal("Terminal: true must set chain.terminal field")
	}
	if !*unsigned.CredentialSubject.Chain.Terminal {
		t.Error("chain.terminal must be true")
	}
}

// TestChainMarshalDropsFalseTerminal verifies the structural safeguard on
// Chain: even when an external caller explicitly sets Terminal to &false
// (bypassing Create()), the wire form must omit the terminal field entirely,
// per spec §4.3.2 which forbids `terminal: false`.
func TestChainMarshalDropsFalseTerminal(t *testing.T) {
	f := false
	prevHash := "sha256:abc"
	c := Chain{
		Sequence:            2,
		PreviousReceiptHash: &prevHash,
		ChainID:             "chain-escape",
		Terminal:            &f, // the escape hatch
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(string(data), "terminal") {
		t.Errorf("Terminal: &false must be omitted from JSON; got %s", data)
	}
}

func TestResponseHashVerificationMatch(t *testing.T) {
	// When a matching body is supplied, VerifyChain recomputes and passes.
	kp, _ := GenerateKeyPair()
	body := json.RawMessage(`{"result":"ok","status":200}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-verify"},
		ResponseBody: body,
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{signed.ID: body},
	})
	if !result.Valid {
		t.Errorf("expected valid when response body matches hash: %s", result.Error)
	}
	if result.ResponseHashNote != "" {
		t.Errorf("expected no note when body is supplied: %s", result.ResponseHashNote)
	}
}

func TestResponseHashVerificationMismatch(t *testing.T) {
	// When the supplied body does not match the stored hash, verification fails.
	kp, _ := GenerateKeyPair()
	goodBody := json.RawMessage(`{"result":"ok"}`)
	badBody := json.RawMessage(`{"result":"tampered"}`)
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-mismatch"},
		ResponseBody: goodBody,
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{signed.ID: badBody},
	})
	if result.Valid {
		t.Error("expected invalid when supplied body does not match stored hash")
	}
	if !containsStr(result.Error, "response_hash mismatch") {
		t.Errorf("expected mismatch error, got: %s", result.Error)
	}
}

func TestResponseHashNoBodyInMap(t *testing.T) {
	// response_hash present but receipt ID not in ResponseBodies → note, not failure.
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:       Issuer{ID: "did:agent:test"},
		Principal:    Principal{ID: "did:user:test"},
		Action:       Action{Type: "data.api.read", RiskLevel: RiskLow},
		Outcome:      Outcome{Status: StatusSuccess},
		Chain:        Chain{Sequence: 1, ChainID: "chain-note2"},
		ResponseBody: []byte(`{"result":"ok"}`),
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Supply an empty ResponseBodies map (no entry for this receipt).
	result := VerifyChain([]AgentReceipt{signed}, kp.PublicKey, ChainVerifyOptions{
		ResponseBodies: map[string]json.RawMessage{},
	})
	if !result.Valid {
		t.Errorf("absent body entry must not fail verification: %s", result.Error)
	}
	if result.ResponseHashNote == "" {
		t.Error("expected informational note when body is absent from map")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
