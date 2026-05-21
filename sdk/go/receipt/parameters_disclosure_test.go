package receipt

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// pdAlicePub returns the RFC 7748 §6.1 Alice X25519 public key (forensic
// test recipient 1). The bytes are duplicated locally rather than sharing
// disclosure_test.go's constants so the two test files stay independently
// readable.
func pdAlicePub(t *testing.T) []byte {
	t.Helper()
	const alicePubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	pub, err := hex.DecodeString(alicePubHex)
	if err != nil {
		t.Fatalf("decode alice pub: %v", err)
	}
	return pub
}

func pdAlicePriv(t *testing.T) []byte {
	t.Helper()
	const alicePrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" //nolint:gosec
	priv, err := hex.DecodeString(alicePrivHex)
	if err != nil {
		t.Fatalf("decode alice priv: %v", err)
	}
	return priv
}

func pdEncrypt(t *testing.T, params map[string]any) *DisclosureEnvelope {
	t.Helper()
	env, err := EncryptDisclosure(params, pdAlicePub(t), "did:key:test#enc-1")
	if err != nil {
		t.Fatalf("EncryptDisclosure: %v", err)
	}
	return env
}

// TestParametersDisclosureEnvelopeRoundTrip verifies that an HPKE envelope
// attached to Action.ParametersDisclosure (ADR-0012 amendment 2026-05-18)
// survives JSON marshal/unmarshal and that all envelope fields are preserved.
func TestParametersDisclosureEnvelopeRoundTrip(t *testing.T) {
	env := pdEncrypt(t, map[string]any{
		"command": "echo build",
		"user":    "ci",
	})

	action := Action{
		ID:                   "act_test",
		Type:                 "filesystem.file.read",
		RiskLevel:            RiskLow,
		ParametersHash:       "sha256:deadbeef",
		ParametersDisclosure: env,
		Timestamp:            "2026-04-28T00:00:00Z",
	}

	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal action: %v", err)
	}
	if !strings.Contains(string(encoded), `"parameters_disclosure"`) {
		t.Fatalf("expected parameters_disclosure in encoded JSON, got %s", encoded)
	}
	for _, want := range []string{`"v":"1"`, `"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm"`, `"recipients":[`, `"ct":"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("encoded action missing %s; got %s", want, encoded)
		}
	}

	var decoded Action
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal action: %v", err)
	}
	if decoded.ParametersDisclosure == nil {
		t.Fatal("decoded ParametersDisclosure is nil")
	}
	if decoded.ParametersDisclosure.V != env.V {
		t.Errorf("decoded v = %q, want %q", decoded.ParametersDisclosure.V, env.V)
	}
	if decoded.ParametersDisclosure.Alg != env.Alg {
		t.Errorf("decoded alg = %q, want %q", decoded.ParametersDisclosure.Alg, env.Alg)
	}
	if decoded.ParametersDisclosure.CT != env.CT {
		t.Errorf("decoded ct mismatch")
	}
	if len(decoded.ParametersDisclosure.Recipients) != 1 {
		t.Fatalf("decoded recipients len = %d, want 1", len(decoded.ParametersDisclosure.Recipients))
	}
	if decoded.ParametersDisclosure.Recipients[0].KID != env.Recipients[0].KID {
		t.Errorf("decoded kid mismatch")
	}
	if decoded.ParametersDisclosure.Recipients[0].Enc != env.Recipients[0].Enc {
		t.Errorf("decoded enc mismatch")
	}
}

// TestParametersDisclosureEnvelopeOmitEmpty verifies the field is omitted
// from JSON when the pointer is nil so receipts without disclosure data
// canonicalize identically to legacy receipts of the same logical shape.
func TestParametersDisclosureEnvelopeOmitEmpty(t *testing.T) {
	action := Action{
		ID:                   "act_test",
		Type:                 "filesystem.file.read",
		RiskLevel:            RiskLow,
		ParametersDisclosure: nil,
		Timestamp:            "2026-04-28T00:00:00Z",
	}
	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "parameters_disclosure") {
		t.Errorf("expected parameters_disclosure to be omitted, got %s", encoded)
	}
}

// TestParametersDisclosureEnvelopeCanonicalIncluded verifies the field is
// included in the RFC 8785 canonical form (envelope keys sorted alphabetically:
// alg, ct, recipients, v) and that removing it changes the receipt hash. The
// hash MUST commit to the envelope ciphertext.
func TestParametersDisclosureEnvelopeCanonicalIncluded(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	env := pdEncrypt(t, map[string]any{"path": "/etc/hosts"})

	withDisclosure := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action: Action{
			ID:                   "act_fixed",
			Type:                 "filesystem.file.read",
			RiskLevel:            RiskLow,
			Timestamp:            "2026-04-28T00:00:00Z",
			ParametersDisclosure: env,
		},
		Outcome: Outcome{Status: StatusSuccess},
		Chain:   Chain{Sequence: 1, ChainID: "chain-1"},
	})
	withDisclosure.ID = "urn:receipt:fixed"
	withDisclosure.IssuanceDate = "2026-04-28T00:00:00Z"

	withoutDisclosure := withDisclosure
	subjectCopy := withDisclosure.CredentialSubject
	actionCopy := subjectCopy.Action
	actionCopy.ParametersDisclosure = nil
	subjectCopy.Action = actionCopy
	withoutDisclosure.CredentialSubject = subjectCopy

	canonWith, err := Canonicalize(withDisclosure)
	if err != nil {
		t.Fatalf("canonicalize with: %v", err)
	}
	if !strings.Contains(canonWith, `"parameters_disclosure":{"alg":"hpke-x25519-hkdf-sha256-aes-256-gcm"`) {
		t.Errorf("canonical form missing parameters_disclosure envelope head: %s", canonWith)
	}

	canonWithout, err := Canonicalize(withoutDisclosure)
	if err != nil {
		t.Fatalf("canonicalize without: %v", err)
	}
	if canonWith == canonWithout {
		t.Error("expected canonical forms to differ when disclosure is removed")
	}

	signedWith, err := Sign(withDisclosure, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	signedWithout, err := Sign(withoutDisclosure, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	hashWith, err := HashReceipt(signedWith)
	if err != nil {
		t.Fatal(err)
	}
	hashWithout, err := HashReceipt(signedWithout)
	if err != nil {
		t.Fatal(err)
	}
	if hashWith == hashWithout {
		t.Error("expected receipt hashes to differ when disclosure is removed")
	}
}

// TestParametersDisclosureEnvelopeRoundTripDecrypts is the headline forensic
// invariant: an envelope embedded in a signed receipt and pulled back out via
// JSON unmarshal MUST decrypt to the original plaintext parameters with the
// matching private key. If this regresses, the disclosure pipeline is broken
// even when signature verification still passes.
func TestParametersDisclosureEnvelopeRoundTripDecrypts(t *testing.T) {
	params := map[string]any{
		"command": "echo build",
		"user":    "ci",
	}
	env := pdEncrypt(t, params)

	action := Action{
		ID:                   "act_test",
		Type:                 "filesystem.file.read",
		RiskLevel:            RiskLow,
		ParametersDisclosure: env,
		Timestamp:            "2026-04-28T00:00:00Z",
	}
	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Action
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := DecryptDisclosure(decoded.ParametersDisclosure, pdAlicePriv(t))
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if got["command"] != params["command"] {
		t.Errorf("decrypted command = %v, want %v", got["command"], params["command"])
	}
	if got["user"] != params["user"] {
		t.Errorf("decrypted user = %v, want %v", got["user"], params["user"])
	}
}
