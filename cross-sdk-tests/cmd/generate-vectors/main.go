// generate_go_vectors reads ts_vectors.json, signs the same unsigned receipt
// with the Go SDK using the shared keypair, and writes go_vectors.json.
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
}
