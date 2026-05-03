package receipt

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateKeyPairAndSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp.PublicKey == "" || kp.PrivateKey == "" {
		t.Fatal("expected non-empty keys")
	}

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}

	if signed.Proof.Type != "Ed25519Signature2020" {
		t.Errorf("expected Ed25519Signature2020, got %s", signed.Proof.Type)
	}
	if signed.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("expected assertionMethod, got %s", signed.Proof.ProofPurpose)
	}
	if signed.Proof.ProofValue == "" {
		t.Fatal("expected non-empty proof value")
	}
	if signed.Proof.ProofValue[0] != 'u' {
		t.Errorf("expected multibase prefix 'u', got %c", signed.Proof.ProofValue[0])
	}

	valid, err := Verify(signed, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected signature to be valid")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, _ := Sign(unsigned, kp1.PrivateKey, "did:agent:test#key-1")

	valid, err := Verify(signed, kp2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected signature to be invalid with wrong key")
	}
}

func TestSignRejectsEmptyPEM(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err := Sign(unsigned, "", "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for empty PEM key")
	}
}

func TestSignRejectsGarbagePEM(t *testing.T) {
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err := Sign(unsigned, "not-a-pem-string!!!", "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for garbage PEM string")
	}
}

func TestVerifyRejectsWrongProofType(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}
	// proof.type lives outside the signed bytes, so swapping it here leaves
	// the Ed25519 signature mathematically valid. Verify MUST still reject
	// the receipt — a verifier that ignores proof.type lets attackers swap in
	// a different scheme name and pass off a forged-but-structurally-valid
	// receipt.
	signed.Proof.Type = "RsaSignature2018"

	valid, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Error("expected error for wrong proof.type")
	}
	if valid {
		t.Error("expected Verify=false for wrong proof.type")
	}
}

func TestVerifyRejectsEmptyProofValue(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	signed.Proof.ProofValue = ""
	_, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty proof value")
	}
}

func TestVerifyRejectsWrongLengthSignature(t *testing.T) {
	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Valid base64 but too short (only 10 bytes).
	short := base64.RawURLEncoding.EncodeToString([]byte("tooshort!!"))
	signed.Proof.ProofValue = "u" + short
	_, err := Verify(signed, kp.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

func TestSignRejectsRSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	_, err = Sign(unsigned, string(rsaPEM), "did:agent:test#key-1")
	if err == nil {
		t.Fatal("expected error for RSA key")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Errorf("expected 'not Ed25519' error, got: %v", err)
	}
}

func TestVerifyRejectsRSAPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kp, _ := GenerateKeyPair()
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	_, err = Verify(signed, string(rsaPubPEM))
	if err == nil {
		t.Fatal("expected error for RSA public key")
	}
	if !strings.Contains(err.Error(), "not Ed25519") {
		t.Errorf("expected 'not Ed25519' error, got: %v", err)
	}
}

func TestVerifyRejectsTamperedReceipt(t *testing.T) {
	kp, _ := GenerateKeyPair()

	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "unknown", RiskLevel: RiskMedium},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	signed, _ := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")

	// Tamper with the receipt.
	signed.CredentialSubject.Action.Type = "filesystem.file.delete"

	valid, err := Verify(signed, kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("expected tampered receipt to fail verification")
	}
}
