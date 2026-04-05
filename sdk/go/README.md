<div align="center">

# sdk-go

### Go SDK for the Action Receipts protocol

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

**Cryptographically signed audit trails for AI agent actions.**

[Spec](https://github.com/agent-receipts/spec) &bull; [TypeScript SDK](https://github.com/agent-receipts/ar/tree/main/sdk/ts) &bull; [Python SDK](https://github.com/agent-receipts/ar/tree/main/sdk/py)

</div>

---

## Install

```sh
go get github.com/agent-receipts/sdk-go
```

## Packages

| Package | Description |
|---------|-------------|
| `receipt` | Create, sign (Ed25519), verify, and hash-chain Action Receipts (W3C Verifiable Credentials) |
| `taxonomy` | Built-in action type registry (15 types), tool call classification, custom mappings |
| `store` | SQLite-backed receipt persistence, query, stats, and chain verification |

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/agent-receipts/sdk-go/receipt"
	"github.com/agent-receipts/sdk-go/store"
	"github.com/agent-receipts/sdk-go/taxonomy"
)

func main() {
	// Generate an Ed25519 key pair
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Classify a tool call
	mappings := []taxonomy.TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
	}
	class := taxonomy.ClassifyToolCall("read_file", mappings)

	// Create an unsigned receipt
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:my-proxy"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action:    receipt.Action{Type: class.ActionType, RiskLevel: class.RiskLevel},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: 1, ChainID: "session-001"},
	})

	// Sign it
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:my-proxy#key-1")
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature
	valid, err := receipt.Verify(signed, kp.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature valid: %v\n", valid)

	// Persist to SQLite
	s, err := store.Open("receipts.db")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	hash, _ := receipt.HashReceipt(signed)
	if err := s.Insert(signed, hash); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Receipt %s stored\n", signed.ID)
}
```

## License

Apache 2.0
