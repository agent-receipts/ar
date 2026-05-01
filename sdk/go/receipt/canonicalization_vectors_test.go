//go:build integration

package receipt

// Test runner for cross-sdk-tests/canonicalization_vectors.json (ADR-0009).
//
// This file implements the requirements from the spec:
//   - For each vector in canonicalization_vectors: Canonicalize(input) must equal canonical.
//   - For each vector in receipt_hash_vectors: HashReceipt(receipt) must equal expectedHash
//     (skip vectors with "COMPUTE_AT_COMMIT_TIME"; treat "SAME_AS_*" as equality invariants).
//   - For receipt_signature_preservation_legacy_0_2_0: verify existing proofs still verify.
//
// Gated behind the `integration` build tag so `go test ./...` for the
// standalone sdk/go module (without the monorepo's cross-sdk-tests/
// sibling directory) still succeeds. CI runs with
// `go test -tags=integration ./...` to exercise these vectors.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorFile is the parsed canonicalization_vectors.json structure.
type vectorFile struct {
	CanonVectors   []canonVector   `json:"canonicalization_vectors"`
	ReceiptVectors []receiptVector `json:"receipt_hash_vectors"`
}

type canonVector struct {
	Name        string          `json:"name"`
	Rule        string          `json:"rule"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Canonical   string          `json:"canonical"`
	// optional fields only present on some vectors
	ExpectedHash string `json:"expectedHash"`
}

type receiptVector struct {
	Name         string          `json:"name"`
	Rule         string          `json:"rule"`
	Description  string          `json:"description"`
	Receipt      json.RawMessage `json:"receipt"`
	ExpectedHash string          `json:"expectedHash"`
	MustContain  string          `json:"mustContainSubstring"`
	ReceiptsFrom string          `json:"receiptsFrom"`
	Invariant    string          `json:"invariant"`
}

// v020VectorFile holds the legacy v020 vectors for the signature-preservation test.
type v020VectorFile struct {
	Keys struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	} `json:"keys"`
	TerminalChain struct {
		Receipts []json.RawMessage `json:"receipts"`
	} `json:"terminalChain"`
	ParametersDisclosureReceipt struct {
		Receipt             json.RawMessage `json:"receipt"`
		ExpectedReceiptHash string          `json:"expectedReceiptHash"`
		ExpectedValid       bool            `json:"expectedValid"`
	} `json:"parametersDisclosureReceipt"`
}

const vectorsPath = "../../../cross-sdk-tests/canonicalization_vectors.json"
const v020VectorsPath = "../../../cross-sdk-tests/v020_vectors.json"

func loadCanonVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join(filepath.Dir("."), vectorsPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonicalization_vectors.json: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse canonicalization_vectors.json: %v", err)
	}
	return vf
}

// TestCanonVectors runs each vector in the canonicalization_vectors array.
func TestCanonVectors(t *testing.T) {
	vf := loadCanonVectors(t)

	for _, v := range vf.CanonVectors {
		v := v // capture
		t.Run(v.Name, func(t *testing.T) {
			// Unmarshal the raw JSON input to any.
			var input any
			if err := json.Unmarshal(v.Input, &input); err != nil {
				t.Fatalf("unmarshal input: %v", err)
			}

			// Note: there is no test-level special-casing for any vector here.
			// The harness always unmarshals v.Input via encoding/json and passes
			// the result to Canonicalize. For number_negative_zero, the vector
			// input is the float literal -0.0, which json.Unmarshal preserves
			// as IEEE 754 negative zero in float64; canonicalizeNumber's n == 0
			// branch then emits the RFC 8785 canonical form "0".

			got, err := Canonicalize(input)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if got != v.Canonical {
				t.Errorf("Canonicalize(%s)\n  got:  %s\n  want: %s", v.Input, got, v.Canonical)
			}

			// For parameters_hash vectors that have an expectedHash, also verify SHA-256.
			if v.ExpectedHash != "" && v.ExpectedHash != "COMPUTE_AT_COMMIT_TIME" {
				h := sha256.Sum256([]byte(got))
				gotHash := "sha256:" + hex.EncodeToString(h[:])
				if gotHash != v.ExpectedHash {
					t.Errorf("SHA-256 of canonical\n  got:  %s\n  want: %s", gotHash, v.ExpectedHash)
				}
			}
		})
	}
}

// TestReceiptHashVectors runs each vector in the receipt_hash_vectors array.
func TestReceiptHashVectors(t *testing.T) {
	vf := loadCanonVectors(t)

	// Collect hashes for SAME_AS_ resolution after all subtests run.
	computed := make(map[string]string) // name → "sha256:..."

	for _, v := range vf.ReceiptVectors {
		v := v
		if v.ReceiptsFrom != "" {
			continue // signature-preservation handled separately
		}

		t.Run(v.Name, func(t *testing.T) {
			// Deserialise into AgentReceipt. Per Go's encoding/json semantics,
			// unmarshalling JSON `null` into a non-pointer string field leaves
			// the Go field at its zero value ("") with no error — so optional
			// fields like outcome.error, action.trusted_timestamp and
			// authorization.grant_ref come through as "", and omitempty then
			// drops them from the canonical form. This is how the Go SDK
			// realises ADR-0009 Rule 2 for vectors that send `null` for
			// optional fields (vs Python/TS which need an explicit
			// strip-optional-nulls pass over a map-shaped receipt).
			// The required-nullable previous_receipt_hash is a *string so its
			// JSON null is preserved as (*string)(nil) and re-emitted as null.
			var receipt AgentReceipt
			if err := json.Unmarshal(v.Receipt, &receipt); err != nil {
				t.Fatalf("unmarshal receipt into AgentReceipt: %v", err)
			}

			gotHash, err := HashReceipt(receipt)
			if err != nil {
				t.Fatalf("HashReceipt: %v", err)
			}
			computed[v.Name] = gotHash

			// mustContainSubstring: check the canonical form of the unsigned receipt.
			if v.MustContain != "" {
				unsigned := UnsignedAgentReceipt{
					Context:           receipt.Context,
					ID:                receipt.ID,
					Type:              receipt.Type,
					Version:           receipt.Version,
					Issuer:            receipt.Issuer,
					IssuanceDate:      receipt.IssuanceDate,
					CredentialSubject: receipt.CredentialSubject,
				}
				canonical, err := Canonicalize(unsigned)
				if err != nil {
					t.Fatalf("Canonicalize unsigned: %v", err)
				}
				if !strings.Contains(canonical, v.MustContain) {
					t.Errorf("canonical output missing required substring %q\n  canonical: %s", v.MustContain, canonical)
				}
			}

			switch {
			case v.ExpectedHash == "" || v.ExpectedHash == "COMPUTE_AT_COMMIT_TIME":
				// Not yet populated — nothing to assert.
			case strings.HasPrefix(v.ExpectedHash, "SAME_AS_"):
				// Deferred until after all subtests complete.
			default:
				if gotHash != v.ExpectedHash {
					t.Errorf("HashReceipt\n  got:  %s\n  want: %s", gotHash, v.ExpectedHash)
				}
			}
		})
	}

	// Resolve SAME_AS_ invariants.
	for _, v := range vf.ReceiptVectors {
		if !strings.HasPrefix(v.ExpectedHash, "SAME_AS_") {
			continue
		}
		refName := strings.TrimPrefix(v.ExpectedHash, "SAME_AS_")
		refHash, ok := computed[refName]
		if !ok {
			t.Errorf("vector %s: SAME_AS_%s: reference vector not found", v.Name, refName)
			continue
		}
		myHash, ok := computed[v.Name]
		if !ok {
			t.Errorf("vector %s: not computed (subtest may have failed)", v.Name)
			continue
		}
		if myHash != refHash {
			t.Errorf("vector %s: expected same hash as %s\n  got:  %s\n  want: %s",
				v.Name, refName, myHash, refHash)
		}
	}
}

// TestSignaturePreservationLegacy_0_2_0 verifies that the post-sweep canonicaliser
// produces identical canonical bytes for receipts signed under the pre-sweep (0.2.0)
// canonicaliser, and that existing Ed25519 proofs still verify.
func TestSignaturePreservationLegacy_0_2_0(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(filepath.Dir("."), v020VectorsPath))
	if err != nil {
		t.Fatalf("read v020_vectors.json: %v", err)
	}
	var vf v020VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse v020_vectors.json: %v", err)
	}
	if len(vf.TerminalChain.Receipts) == 0 {
		t.Fatal("v020_vectors.json: terminalChain.receipts is empty")
	}

	for i, raw := range vf.TerminalChain.Receipts {
		var signed AgentReceipt
		if err := json.Unmarshal(raw, &signed); err != nil {
			t.Fatalf("receipt[%d]: unmarshal: %v", i, err)
		}

		// Verify signature still validates.
		valid, err := Verify(signed, vf.Keys.PublicKey)
		if err != nil {
			t.Errorf("receipt[%d] (%s): Verify error: %v", i, signed.ID, err)
			continue
		}
		if !valid {
			t.Errorf("receipt[%d] (%s): signature no longer verifies after canonicaliser sweep", i, signed.ID)
		}
	}
}

// TestParametersDisclosureReceipt verifies the cross-SDK parameters_disclosure
// receipt vector: the signature must verify and HashReceipt must reproduce
// expectedReceiptHash byte-for-byte (ADR-0012 Phase A).
func TestParametersDisclosureReceipt(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(filepath.Dir("."), v020VectorsPath))
	if err != nil {
		t.Fatalf("read v020_vectors.json: %v", err)
	}
	var vf v020VectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse v020_vectors.json: %v", err)
	}
	if len(vf.ParametersDisclosureReceipt.Receipt) == 0 {
		t.Fatal("v020_vectors.json: parametersDisclosureReceipt.receipt is empty")
	}

	var signed AgentReceipt
	if err := json.Unmarshal(vf.ParametersDisclosureReceipt.Receipt, &signed); err != nil {
		t.Fatalf("unmarshal parameters_disclosure receipt: %v", err)
	}

	valid, err := Verify(signed, vf.Keys.PublicKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Fatal("parameters_disclosure receipt failed signature verification")
	}

	gotHash, err := HashReceipt(signed)
	if err != nil {
		t.Fatalf("HashReceipt: %v", err)
	}
	if gotHash != vf.ParametersDisclosureReceipt.ExpectedReceiptHash {
		t.Errorf("HashReceipt\n  got:  %s\n  want: %s", gotHash, vf.ParametersDisclosureReceipt.ExpectedReceiptHash)
	}
}
