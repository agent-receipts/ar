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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
//
// As of the v0.3.0 envelope migration (ADR-0012 amendment 2026-05-18) the
// Go SDK's typed Action.ParametersDisclosure is *DisclosureEnvelope and can
// no longer round-trip the legacy flat-map shape that some vectors pin
// (e.g. receipt_all_optional_present). Unmarshalling into the typed struct
// would silently drop or mangle that field and mismatch the pinned hash.
// The test therefore parses to map[string]any, runs an explicit
// strip-optional-nulls pass (Rule 2 of ADR-0009), and canonicalises the map
// directly. This mirrors how the TS and Python SDKs validate this vector
// set today; the canonicaliser remains the unit under test, not the typed
// struct.
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
			var receiptMap map[string]any
			if err := json.Unmarshal(v.Receipt, &receiptMap); err != nil {
				t.Fatalf("unmarshal receipt to map: %v", err)
			}
			stripOptionalNulls(receiptMap)

			// "proof" is the only field excluded from the hash; vectors here
			// publish unsigned receipts so the field is typically absent, but
			// strip it if present so we never accidentally include it.
			delete(receiptMap, "proof")

			canonical, err := Canonicalize(receiptMap)
			if err != nil {
				t.Fatalf("Canonicalize receipt: %v", err)
			}
			gotHash := SHA256Hash(canonical)
			computed[v.Name] = gotHash

			if v.MustContain != "" {
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

// TestParametersDisclosureReceipt verifies the legacy v0.2.1 cross-SDK
// parameters_disclosure receipt vector: the signature must verify and the
// canonicalized-then-hashed receipt must reproduce expectedReceiptHash
// byte-for-byte (ADR-0012 Phase A).
//
// The v020 vector pins the *legacy* flat-map shape of parameters_disclosure
// (string→string), which the Go SDK can no longer round-trip through
// receipt.AgentReceipt as of the v0.3.0 envelope migration (ADR-0012
// amendment 2026-05-18): Action.ParametersDisclosure is now
// *DisclosureEnvelope and would silently drop the legacy shape on
// json.Unmarshal, mangling the hash.
//
// Approach: mirror cross-sdk-tests/v030_vectors_test.go — parse to
// map[string]any so the legacy shape survives the round trip; canonicalise
// the unsigned portion via the SDK's Canonicalize; verify the proof at the
// crypto/ed25519 layer. The canonicaliser remains the unit under test; the
// typed struct is intentionally bypassed because it cannot model the legacy
// receipt format losslessly.
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

	var receiptMap map[string]any
	if err := json.Unmarshal(vf.ParametersDisclosureReceipt.Receipt, &receiptMap); err != nil {
		t.Fatalf("unmarshal parameters_disclosure receipt to map: %v", err)
	}
	proofMap, ok := receiptMap["proof"].(map[string]any)
	if !ok {
		t.Fatal("receipt missing proof object")
	}
	proofValue, _ := proofMap["proofValue"].(string)
	if len(proofValue) < 2 || proofValue[0] != 'u' {
		t.Fatalf("proof.proofValue %q: missing u multibase prefix", proofValue)
	}
	sig, err := base64.RawURLEncoding.DecodeString(proofValue[1:])
	if err != nil {
		t.Fatalf("decode proofValue: %v", err)
	}

	// Strip proof; canonicalize the remainder.
	unsigned := make(map[string]any, len(receiptMap)-1)
	for k, v := range receiptMap {
		if k == "proof" {
			continue
		}
		unsigned[k] = v
	}
	canonical, err := Canonicalize(unsigned)
	if err != nil {
		t.Fatalf("Canonicalize unsigned: %v", err)
	}

	pub, err := parseEd25519PublicPEMLocal(vf.Keys.PublicKey)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("parameters_disclosure receipt failed signature verification")
	}

	h := sha256.Sum256([]byte(canonical))
	gotHash := "sha256:" + hex.EncodeToString(h[:])
	if gotHash != vf.ParametersDisclosureReceipt.ExpectedReceiptHash {
		t.Errorf("receipt hash\n  got:  %s\n  want: %s", gotHash, vf.ParametersDisclosureReceipt.ExpectedReceiptHash)
	}
}

// stripOptionalNulls walks a receipt map and removes keys whose value is null,
// implementing ADR-0009 Rule 2 explicitly. The TS and Python SDKs already do
// this; the Go SDK previously rode on encoding/json's "null → zero value →
// omitempty" sequence over its typed Action struct, but the v0.3.0 envelope
// migration (ADR-0012 amendment 2026-05-18) makes the typed struct unable to
// model the legacy flat-map parameters_disclosure shape losslessly. The
// receipt-hash test pins a single allowlisted required-nullable path
// (credentialSubject.chain.previous_receipt_hash) which must remain literal
// null in the canonical bytes; every other null is treated as "absent" and
// dropped before canonicalisation.
func stripOptionalNulls(receipt map[string]any) {
	requiredNullable := func(path []string) bool {
		// Only one path is required-nullable per the spec today.
		return len(path) == 3 &&
			path[0] == "credentialSubject" &&
			path[1] == "chain" &&
			path[2] == "previous_receipt_hash"
	}
	var walk func(node map[string]any, path []string)
	walk = func(node map[string]any, path []string) {
		for k, v := range node {
			child := append(path, k)
			if v == nil {
				if !requiredNullable(child) {
					delete(node, k)
				}
				continue
			}
			if sub, ok := v.(map[string]any); ok {
				walk(sub, child)
			}
		}
	}
	walk(receipt, nil)
}

// parseEd25519PublicPEMLocal is a test-local copy of the PEM parser used by
// signing.go, kept here to avoid touching the SDK's unexported helpers.
func parseEd25519PublicPEMLocal(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("decode PEM public key: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return edKey, nil
}
