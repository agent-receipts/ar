// generate_go_vectors reads ts_vectors.json, signs the same unsigned receipt
// with the Go SDK using the shared keypair, and writes go_vectors.json and
// v020_vectors.json.
//
// Usage: go run ./cmd/generate-vectors
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

type vectors struct {
	Keys             keysSection             `json:"keys"`
	Canonicalization canonicalizationSection `json:"canonicalization"`
	Hashing          hashingSection          `json:"hashing"`
	Signing          signingSection          `json:"signing"`
}

type keysSection struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type canonicalizationSection struct {
	SimpleInput     any    `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptInput    any    `json:"receiptInput"`
	ReceiptExpected string `json:"receiptExpected"`
}

type hashingSection struct {
	SimpleInput     string `json:"simpleInput"`
	SimpleExpected  string `json:"simpleExpected"`
	ReceiptExpected string `json:"receiptExpected"`
}

type signingSection struct {
	Unsigned           json.RawMessage `json:"unsigned"`
	Signed             json.RawMessage `json:"signed"`
	VerificationMethod string          `json:"verificationMethod"`
}

// v020Vectors holds ADR-0008 cross-SDK test vectors.
type v020Vectors struct {
	Version      string               `json:"version"`
	Keys         keysSection          `json:"keys"`
	ResponseHash responseHashSection  `json:"responseHash"`
	TerminalChain terminalChainSection `json:"terminalChain"`
}

type responseHashSection struct {
	RawResponse      map[string]any `json:"rawResponse"`
	RedactedResponse map[string]any `json:"redactedResponse"`
	ExpectedHash     string         `json:"expectedHash"`
}

type terminalChainSection struct {
	Receipts                           []json.RawMessage `json:"receipts"`
	ExpectedValid                      bool              `json:"expectedValid"`
	ExpectedValidWithRequireTerminal   bool              `json:"expectedValidWithRequireTerminal"`
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	// Read the TS vectors to get the shared keypair and unsigned receipt.
	// Resolve paths relative to the module root (cross-sdk-tests/) so this
	// works when invoked as `go run ./cmd/generate-vectors` from there.
	tsData, err := os.ReadFile("../sdk/py/tests/fixtures/ts_vectors.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read ts_vectors.json: %v\n", err)
		os.Exit(1)
	}

	var tsVectors vectors
	if err := json.Unmarshal(tsData, &tsVectors); err != nil {
		fmt.Fprintf(os.Stderr, "parse ts_vectors.json: %v\n", err)
		os.Exit(1)
	}

	// Parse the unsigned receipt into the Go SDK type.
	var unsigned receipt.UnsignedAgentReceipt
	if err := json.Unmarshal(tsVectors.Signing.Unsigned, &unsigned); err != nil {
		fmt.Fprintf(os.Stderr, "parse unsigned receipt: %v\n", err)
		os.Exit(1)
	}

	// Canonicalize the simple input and receipt input.
	simpleCanonical, err := receipt.Canonicalize(tsVectors.Canonicalization.SimpleInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize simple: %v\n", err)
		os.Exit(1)
	}

	receiptCanonical, err := receipt.Canonicalize(tsVectors.Canonicalization.ReceiptInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize receipt: %v\n", err)
		os.Exit(1)
	}

	// Hash.
	simpleHash := receipt.SHA256Hash(tsVectors.Hashing.SimpleInput)

	// Sign the unsigned receipt with the Go SDK.
	signed, err := receipt.Sign(unsigned, tsVectors.Keys.PrivateKey, tsVectors.Signing.VerificationMethod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign receipt: %v\n", err)
		os.Exit(1)
	}

	// Hash the signed receipt.
	receiptHash, err := receipt.HashReceipt(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash receipt: %v\n", err)
		os.Exit(1)
	}

	// Build the Go vectors output.
	signedJSON, err := json.Marshal(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal signed: %v\n", err)
		os.Exit(1)
	}

	goVectors := vectors{
		Keys: tsVectors.Keys,
		Canonicalization: canonicalizationSection{
			SimpleInput:     tsVectors.Canonicalization.SimpleInput,
			SimpleExpected:  simpleCanonical,
			ReceiptInput:    tsVectors.Canonicalization.ReceiptInput,
			ReceiptExpected: receiptCanonical,
		},
		Hashing: hashingSection{
			SimpleInput:     tsVectors.Hashing.SimpleInput,
			SimpleExpected:  simpleHash,
			ReceiptExpected: receiptHash,
		},
		Signing: signingSection{
			Unsigned:           tsVectors.Signing.Unsigned,
			Signed:             json.RawMessage(signedJSON),
			VerificationMethod: tsVectors.Signing.VerificationMethod,
		},
	}

	out, err := json.MarshalIndent(goVectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal output: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile("go_vectors.json", append(out, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write go_vectors.json: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote go_vectors.json")

	// --- v0.2.0 vectors ---
	if err := generateV020Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v020 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v020_vectors.json")
}

// generateV020Vectors builds and writes v020_vectors.json using a fresh key pair.
//
// Fields that Create/Sign populate from the clock and the UUID package are
// overridden with fixed values so the output is byte-identical across runs.
// This keeps the checked-in test vector stable (no spurious diffs on
// regeneration) and makes the file usable as a signature-level cross-SDK
// oracle. Ed25519 is deterministic (RFC 8032), so identical signed bytes
// plus identical key produce identical proofValue.
func generateV020Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-04-22T00:00:00Z"

	// Response hash vectors: redact → canonicalize → SHA-256.
	rawResponse := map[string]any{
		"result":   "ok",
		"password": "super-secret-value",
	}
	redactedResponse := map[string]any{
		"result":   "ok",
		"password": "[REDACTED]",
	}
	redactedJSON, err := json.Marshal(redactedResponse)
	if err != nil {
		return fmt.Errorf("marshal redacted: %w", err)
	}
	canonical, err := receipt.Canonicalize(redactedResponse)
	if err != nil {
		return fmt.Errorf("canonicalize redacted: %w", err)
	}
	expectedHash := receipt.SHA256Hash(canonical)

	// Build a 3-receipt terminal chain using the shared key.
	var prevHash *string
	terminalReceipts := make([]receipt.AgentReceipt, 0, 3)
	for i := 1; i <= 3; i++ {
		isTerminal := i == 3
		r := receipt.Create(receipt.CreateInput{
			Issuer:       receipt.Issuer{ID: "did:agent:test"},
			Principal:    receipt.Principal{ID: "did:user:test"},
			Action:       receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
			Outcome:      receipt.Outcome{Status: receipt.StatusSuccess},
			Chain:        receipt.Chain{Sequence: i, PreviousReceiptHash: prevHash, ChainID: "chain_v020_test"},
			ResponseBody: redactedJSON,
			Terminal:     isTerminal,
		})
		// Override Create-assigned non-deterministic fields (UUIDs, timestamps).
		r.ID = fmt.Sprintf("urn:receipt:v020-terminal-%d", i)
		r.IssuanceDate = fixedTimestamp
		r.CredentialSubject.Action.ID = fmt.Sprintf("act_v020_%d", i)
		r.CredentialSubject.Action.Timestamp = fixedTimestamp

		s, err := receipt.Sign(r, keys.PrivateKey, "did:agent:test#key-1")
		if err != nil {
			return fmt.Errorf("sign receipt %d: %w", i, err)
		}
		// proof.created is outside the signed payload — safe to fix afterwards.
		s.Proof.Created = fixedTimestamp

		terminalReceipts = append(terminalReceipts, s)
		h, err := receipt.HashReceipt(s)
		if err != nil {
			return fmt.Errorf("hash receipt %d: %w", i, err)
		}
		prevHash = &h
	}

	// Verify the chain to confirm it's valid.
	verResult := receipt.VerifyChain(terminalReceipts, keys.PublicKey)
	if !verResult.Valid {
		return fmt.Errorf("generated terminal chain failed verification: %s", verResult.Error)
	}

	// Marshal receipts.
	receiptJSONs := make([]json.RawMessage, len(terminalReceipts))
	for i, r := range terminalReceipts {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal receipt %d: %w", i, err)
		}
		receiptJSONs[i] = json.RawMessage(b)
	}

	v020 := v020Vectors{
		Version: "0.2.0",
		Keys:    keys,
		ResponseHash: responseHashSection{
			RawResponse:      rawResponse,
			RedactedResponse: redactedResponse,
			ExpectedHash:     expectedHash,
		},
		TerminalChain: terminalChainSection{
			Receipts:                         receiptJSONs,
			ExpectedValid:                    true,
			ExpectedValidWithRequireTerminal: true,
		},
	}

	out, err := json.MarshalIndent(v020, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v020 vectors: %w", err)
	}
	return os.WriteFile("v020_vectors.json", append(out, '\n'), 0644)
}
