// generate-vectors is the build script for the pinned cross-SDK test vectors.
// All outputs share a single Ed25519 keypair loaded from the test fixtures so
// that signature bytes can be compared across SDKs.
//
// Outputs:
//   - go_vectors.json — signs the unsigned receipt from ts_vectors.json with
//     the Go SDK; pairs with py_vectors.json / ts_vectors.json to assert
//     byte-identical signatures across the three SDKs at v0.2.x.
//   - v020_vectors.json — pinned v0.2.0 / v0.2.1 fixtures (legacy flat-map
//     parameters_disclosure shape, no envelope).
//   - v030_vectors.json — pinned v0.3.0 fixtures exercising the new
//     envelope-shape parameters_disclosure plus the peer_credential and
//     emitter_metadata typed action fields. Independently constructed
//     (NOT derived from ts_vectors.json); reuses only the shared keypair.
//
// Usage: go run ./cmd/generate-vectors
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	Version                     string                             `json:"version"`
	Keys                        keysSection                        `json:"keys"`
	ResponseHash                responseHashSection                `json:"responseHash"`
	TerminalChain               terminalChainSection               `json:"terminalChain"`
	ParametersDisclosureReceipt parametersDisclosureReceiptSection `json:"parametersDisclosureReceipt"`
}

type responseHashSection struct {
	RawResponse      map[string]any `json:"rawResponse"`
	RedactedResponse map[string]any `json:"redactedResponse"`
	ExpectedHash     string         `json:"expectedHash"`
}

type terminalChainSection struct {
	Receipts                         []json.RawMessage `json:"receipts"`
	ExpectedValid                    bool              `json:"expectedValid"`
	ExpectedValidWithRequireTerminal bool              `json:"expectedValidWithRequireTerminal"`
}

// parametersDisclosureReceiptSection holds a single 0.2.1 signed receipt with
// parameters_disclosure populated. All three SDKs MUST canonicalise, hash, and
// verify it identically (per ADR-0012 Phase A).
type parametersDisclosureReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
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

	// --- v0.3.0 vectors ---
	if err := generateV030Vectors(tsVectors.Keys); err != nil {
		fmt.Fprintf(os.Stderr, "generate v030 vectors: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote v030_vectors.json")
}

// generateV020Vectors builds and writes v020_vectors.json using the shared keypair
// from ts_vectors.json (passed in as keys).
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

	// Single-receipt parameters_disclosure vector (ADR-0012 Phase A, schema 0.2.1).
	// Built standalone (not part of the legacy 0.2.0 chain), signed with the same
	// shared key, deterministic via fixed timestamps and UUID overrides.
	pdReceipt, pdHash, err := generateParametersDisclosureReceipt(keys)
	if err != nil {
		return fmt.Errorf("generate parameters_disclosure receipt: %w", err)
	}
	pdReceiptJSON, err := json.Marshal(pdReceipt)
	if err != nil {
		return fmt.Errorf("marshal parameters_disclosure receipt: %w", err)
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
		ParametersDisclosureReceipt: parametersDisclosureReceiptSection{
			Description:         "Single 0.2.1 signed receipt with action.parameters_disclosure populated. All three SDKs MUST verify the signature and reproduce expectedReceiptHash byte-for-byte (ADR-0012 Phase A; ADR-0009 canonicalisation).",
			Receipt:             json.RawMessage(pdReceiptJSON),
			ExpectedReceiptHash: pdHash,
			ExpectedValid:       true,
		},
	}

	out, err := json.MarshalIndent(v020, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v020 vectors: %w", err)
	}
	return os.WriteFile("v020_vectors.json", append(out, '\n'), 0644)
}

// generateParametersDisclosureReceipt builds a deterministic single-receipt
// vector (schema 0.2.1) with action.parameters_disclosure populated, signs it
// with the shared private key, and returns the signed receipt and its hash.
//
// The receipt deliberately uses a fresh chain (chain_pd_test, sequence 1) so it
// cannot be confused with the legacy 0.2.0 terminalChain — that chain stays
// frozen as the signature-preservation oracle.
func generateParametersDisclosureReceipt(keys keysSection) (receipt.AgentReceipt, string, error) {
	const fixedTimestamp = "2026-04-22T00:00:00Z"

	r := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:test"},
		Principal: receipt.Principal{ID: "did:user:test"},
		Action: receipt.Action{
			Type:      "filesystem.file.read",
			RiskLevel: receipt.RiskLow,
			ParametersDisclosure: map[string]string{
				"command": "echo build",
				"user":    "ci",
			},
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:   receipt.Chain{Sequence: 1, PreviousReceiptHash: nil, ChainID: "chain_pd_test"},
	})
	r.Version = "0.2.1"
	r.ID = "urn:receipt:v021-pd-1"
	r.IssuanceDate = fixedTimestamp
	r.CredentialSubject.Action.ID = "act_v021_pd_1"
	r.CredentialSubject.Action.Timestamp = fixedTimestamp

	signed, err := receipt.Sign(r, keys.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("sign: %w", err)
	}
	signed.Proof.Created = fixedTimestamp

	valid, err := receipt.Verify(signed, keys.PublicKey)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("verify: %w", err)
	}
	if !valid {
		return receipt.AgentReceipt{}, "", fmt.Errorf("generated parameters_disclosure receipt failed verification")
	}

	hash, err := receipt.HashReceipt(signed)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("hash: %w", err)
	}
	return signed, hash, nil
}

// --- v0.3.0 vector generation ---
//
// The v0.3.0 receipt shape introduces three new typed fields on action:
//   - parameters_disclosure as the HPKE envelope (spec/schema parametersDisclosureEnvelope)
//   - peer_credential (OS-attested daemon ↔ SDK boundary metadata)
//   - emitter_metadata (drop_count for synthetic events_dropped receipts)
//
// The Go SDK Action struct still types parameters_disclosure as
// map[string]string (changing that is PR-C's scope, not PR-B). To keep PR-B's
// diff scoped to vectors only, the v030 receipts are built as map[string]any
// trees, signed directly with ed25519 (replicating the SDK's PEM-parse +
// sign-the-JCS-bytes flow), and hashed via the SDK's Canonicalize + SHA256.
//
// The envelope bytes come from spec/test-vectors/disclosure-envelope/vectors.json
// vector-1, which the Go SDK already pins byte-for-byte in
// sdk/go/receipt/disclosure_test.go:TestDeterministicVector1 — so cross-SDK
// reproduction of the same envelope (RFC 9180 §A.1.1 ikmE → Alice public key)
// is verified there, and these vectors just embed the result.

// v030Vectors is the top-level structure of v030_vectors.json.
//
// Mirrors the legacy v020_vectors.json layout (top-level metadata + named
// receipt sections) so the cross-SDK harness can be wired in the same pattern
// across Go, TS, and Py.
type v030Vectors struct {
	Comment        string                       `json:"$comment"`
	Version        string                       `json:"version"`
	Keys           keysSection                  `json:"keys"`
	Envelope       envelopeReceiptSection       `json:"parametersDisclosureEnvelopeReceipt"`
	DaemonAttested daemonAttestedReceiptSection `json:"peerCredentialEmitterMetadataReceipt"`
}

type envelopeReceiptSection struct {
	Description          string          `json:"description"`
	EnvelopeSourceVector string          `json:"envelopeSourceVector"`
	Receipt              json.RawMessage `json:"receipt"`
	ExpectedReceiptHash  string          `json:"expectedReceiptHash"`
	ExpectedValid        bool            `json:"expectedValid"`
}

type daemonAttestedReceiptSection struct {
	Description         string          `json:"description"`
	Receipt             json.RawMessage `json:"receipt"`
	ExpectedReceiptHash string          `json:"expectedReceiptHash"`
	ExpectedValid       bool            `json:"expectedValid"`
}

// Pinned envelope from spec/test-vectors/disclosure-envelope/vectors.json
// (vector-1, RFC 9180 §A.1.1 ikmE encrypting to RFC 7748 §6.1 Alice). The Go
// SDK reproduces this byte-for-byte in
// sdk/go/receipt/disclosure_test.go:TestDeterministicVector1; TS and Py do the
// same in their HPKE tests. Embedding the result here lets the receipt-level
// vector remain deterministic without rerunning HPKE at generation time.
var vector1Envelope = map[string]any{
	"v":   "1",
	"alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
	"recipients": []any{
		map[string]any{
			"kid": "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQUQUaHL9XJ7Z5W#enc-1",
			"enc": "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE",
		},
	},
	"ct": "YGn3i4NpiZxHjeZVggTP8lTxb0ZVdLl-2HjW31qsvo28PjQ_Lt_UQgAMidEXjzwhJPHM7OM",
}

func generateV030Vectors(keys keysSection) error {
	const fixedTimestamp = "2026-05-21T00:00:00Z"

	// --- envelope-shape receipt ---
	envelopeUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:030e0030-0000-4030-a030-000000000001",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.3.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":                    "act_030e0030-0000-4030-a030-000000000001",
				"type":                  "system.command.execute",
				"risk_level":            "high",
				"parameters_disclosure": vector1Envelope,
				"timestamp":             fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v030_envelope_test",
			},
		},
	}
	envelopeSigned, envelopeHash, err := signAndHashMap(envelopeUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("envelope receipt: %w", err)
	}

	// --- peer_credential + emitter_metadata receipt ---
	// Synthetic events_dropped style: daemon-attested peer metadata plus
	// drop_count emitter metadata. Uses POSIX-style values (linux peer) so
	// uid/gid are present; Windows daemons would omit those.
	daemonUnsigned := map[string]any{
		"@context":     []any{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"},
		"id":           "urn:receipt:030e0030-0000-4030-a030-000000000002",
		"type":         []any{"VerifiableCredential", "AgentReceipt"},
		"version":      "0.3.0",
		"issuer":       map[string]any{"id": "did:agent:test"},
		"issuanceDate": fixedTimestamp,
		"credentialSubject": map[string]any{
			"principal": map[string]any{"id": "did:user:test"},
			"action": map[string]any{
				"id":         "act_030e0030-0000-4030-a030-000000000002",
				"type":       "system.events_dropped",
				"risk_level": "low",
				"peer_credential": map[string]any{
					"platform": "linux",
					"pid":      12345,
					"uid":      1000,
					"gid":      1000,
					"exe_path": "/usr/local/bin/some-tool",
				},
				"emitter_metadata": map[string]any{
					"drop_count": 3,
				},
				"timestamp": fixedTimestamp,
			},
			"outcome": map[string]any{"status": "success"},
			"chain": map[string]any{
				"sequence":              1,
				"previous_receipt_hash": nil,
				"chain_id":              "chain_v030_daemon_test",
			},
		},
	}
	daemonSigned, daemonHash, err := signAndHashMap(daemonUnsigned, keys, fixedTimestamp)
	if err != nil {
		return fmt.Errorf("daemon-attested receipt: %w", err)
	}

	out := v030Vectors{
		Comment: "Cross-SDK v0.3.0 test vectors: pins (a) the HPKE envelope shape of action.parameters_disclosure (ADR-0012 amendment 2026-05-18, spec PR #496) and (b) the daemon-attested action.peer_credential / action.emitter_metadata fields (ADR-0010). All three SDKs MUST verify the signatures and reproduce expectedReceiptHash byte-for-byte. Envelope bytes come from spec/test-vectors/disclosure-envelope/vectors.json vector-1 (RFC 9180 §A.1.1 ikmE encrypting to RFC 7748 §6.1 Alice).",
		Version: "0.3.0",
		Keys:    keys,
		Envelope: envelopeReceiptSection{
			Description:          "Signed v0.3.0 receipt whose action.parameters_disclosure carries the HPKE asymmetric envelope (ADR-0012 amendment). Envelope bytes are vector-1 from spec/test-vectors/disclosure-envelope/vectors.json — deterministic against RFC 9180 §A.1.1.",
			EnvelopeSourceVector: "spec/test-vectors/disclosure-envelope/vectors.json#vector-1-single-recipient-small-payload",
			Receipt:              envelopeSigned,
			ExpectedReceiptHash:  envelopeHash,
			ExpectedValid:        true,
		},
		DaemonAttested: daemonAttestedReceiptSection{
			Description:         "Signed v0.3.0 receipt exercising the daemon-attested typed fields: action.peer_credential (linux POSIX peer metadata) and action.emitter_metadata.drop_count (synthetic events_dropped semantics per ADR-0010).",
			Receipt:             daemonSigned,
			ExpectedReceiptHash: daemonHash,
			ExpectedValid:       true,
		},
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal v030 vectors: %w", err)
	}
	return os.WriteFile("v030_vectors.json", append(outBytes, '\n'), 0644)
}

// signAndHashMap signs an unsigned-receipt JSON map with the Ed25519 PEM
// private key from keys, attaches the resulting proof, and returns the signed
// receipt JSON (sorted by JCS at canonicalization time, not at marshal time)
// alongside its receipt hash.
//
// Receipt JSON is built via Go's encoding/json default marshalling (struct or
// map). Verifiers MUST canonicalize before hashing/verifying.
func signAndHashMap(unsigned map[string]any, keys keysSection, fixedTimestamp string) (json.RawMessage, string, error) {
	canonical, err := receipt.Canonicalize(unsigned)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize unsigned: %w", err)
	}
	hash := receipt.SHA256Hash(canonical)

	priv, err := parseEd25519PrivatePEM(keys.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	proofValue := "u" + base64.RawURLEncoding.EncodeToString(sig)

	signed := make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		signed[k] = v
	}
	signed["proof"] = map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            fixedTimestamp,
		"verificationMethod": "did:agent:test#key-1",
		"proofPurpose":       "assertionMethod",
		"proofValue":         proofValue,
	}

	// Sanity-check: verify the signature we just produced against the public key.
	pub, err := parseEd25519PublicPEM(keys.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key: %w", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return nil, "", errors.New("self-verify failed after signing v030 receipt")
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, "", fmt.Errorf("marshal signed: %w", err)
	}
	return json.RawMessage(raw), hash, nil
}

func parseEd25519PrivatePEM(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("decode PEM private key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return edKey, nil
}

func parseEd25519PublicPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("decode PEM public key: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return edKey, nil
}
