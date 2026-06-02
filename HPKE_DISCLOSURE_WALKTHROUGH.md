# HPKE Parameter Disclosure: End-to-End Walkthrough

**Status:** The HPKE disclosure primitives are complete and working across all three SDKs as of v0.3.0 (2026-05-21). This walkthrough shows how to use them *today* via SDK-direct mode.

## What you'll do

1. **Generate a forensic key pair once** — public key shared with emitters, private key stays offline
2. **Encrypt tool parameters to the public key** — happens automatically in the SDK
3. **Emit a signed receipt with encrypted parameters** — the plaintext never appears in the receipt on the wire
4. **Recover the plaintext later** — with the private key, decrypt to get the original parameters back

## Prerequisites

- Go 1.26+ (or TS/Python SDK equivalents)
- `agent-receipts/ar` repo cloned

## Step 1: Generate the forensic key pair

The operator does this once and keeps the private key offline:

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func main() {
	// Generate once, share public key, keep private key offline
	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(fk.PublicKey)
	privB64 := base64.StdEncoding.EncodeToString(fk.PrivateKey)

	fmt.Printf("Public key (share with emitters):\n%s\n\n", pubB64)
	fmt.Printf("Private key (KEEP OFFLINE — store in HSM or separate machine):\n%s\n\n", privB64)
}
```

Output example:
```
Public key (share with emitters):
GhwJEaqrpIjae7SDEkT5jdaz
...

Private key (KEEP OFFLINE — store in HSM or separate machine):
o09kfjNFzKgAMOIl6MDEkNT7
...
```

## Step 2: Emitter encrypts parameters before signing

In your agent, MCP proxy, or tool harness, when you're about to emit a receipt:

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/google/uuid"
)

func main() {
	// The real tool parameters (what the tool actually received)
	toolParams := map[string]any{
		"command": "rm -rf /tmp/old-report.pdf",
	}

	// Load the forensic public key (shared via config/env, not hardcoded)
	pubKeyB64 := "GhwJEaqrpIjae7SDEkT5jdaz..." // from env or config
	pubKey, _ := base64.StdEncoding.DecodeString(pubKeyB64)

	// Encrypt the parameters to the public key
	kid := "sha256:my-forensic-key-fingerprint-1" // or a did:key URL
	env, err := receipt.EncryptDisclosure(toolParams, pubKey, kid)
	if err != nil {
		log.Fatal(err)
	}

	// 1. Create an unsigned receipt with the encrypted disclosure attached
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:   "did:agent:my-agent-instance",
			Name: "MyAgent",
		},
		Principal: receipt.Principal{
			ID:   "did:user:operator-1",
			Type: "HumanPrincipal",
		},
		Action: receipt.Action{
			Type:                 "system.command.execute",
			RiskLevel:            receipt.RiskHigh,
			ParametersDisclosure: env, // <-- attach the encrypted envelope
			Timestamp:            time.Now().UTC().Format(time.RFC3339),
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			ChainID:             "chain_" + uuid.New().String(),
			Sequence:            1,
			PreviousReceiptHash: nil,
		},
	})

	// 2. Sign the receipt (the encrypted disclosure is part of the signed bytes)
	keyProvider, err := receipt.NewGeneratingKeyProvider()
	if err != nil {
		log.Fatal(err)
	}
	keypair, err := keyProvider.GetKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	signed, signErr := receipt.Sign(unsigned, keypair.PrivateKey, "did:agent:my-agent-instance#key-1")
	if signErr != nil {
		log.Fatal(signErr)
	}

	// 3. Serialize to JSON — parameters are opaque ciphertext
	jsonBytes, _ := json.MarshalIndent(signed, "", "  ")
	print("Signed receipt (parameters are encrypted):\n")
	println(string(jsonBytes))
}
```

The emitted receipt contains:
```json
{
  "credentialSubject": {
    "action": {
      "parameters_disclosure": {
        "v": "1",
        "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
        "recipients": [
          {
            "kid": "sha256:my-forensic-key-fingerprint-1",
            "enc": "zzZI3MML74_1OjZe0iDfFTAWOYfLRMFyb9GyMXYH0mY"
          }
        ],
        "ct": "NXfh3fvN0dKc1KWXNDW2WqRBeK1Mgmwj0P7leG35kzCDYu5qUMr-2ZKMRdOWBWtyMbo6GInznKI"
      },
      "parameters_hash": "sha256:..."
    }
  }
}
```

**The plaintext `"command": "rm -rf ..."` never appears.** The `parameters_hash` proves integrity; the ciphertext is opaque to anyone without the forensic private key.

## Step 3: Forensic responder decrypts (later, on demand)

When you need to answer "what command ran?", the holder of the private key decrypts:

```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func main() {
	// Load a receipt from your audit store
	var r receipt.AgentReceipt
	json.Unmarshal(receiptJSON, &r)

	// Load the forensic private key (from HSM, secure vault, or offline storage)
	privKeyB64 := "o09kfjNFzKgAMOIl6MDEkNT7..." // from secure vault
	privKey, _ := base64.StdEncoding.DecodeString(privKeyB64)

	// Decrypt
	env := r.CredentialSubject.Action.ParametersDisclosure
	plaintext, err := receipt.DecryptDisclosure(env, privKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Original tool parameters: %v\n", plaintext)
	// Output: Original tool parameters: map[command:rm -rf /tmp/old-report.pdf]
}
```

## Key properties

| Property | What it means |
|----------|---------------|
| **Hash is always visible** | `action.parameters_hash` proves the parameters haven't been tampered with. This works without the private key. |
| **Ciphertext is opaque** | Without the private key, `parameters_disclosure` is meaningless bytes. |
| **Signature is permanent** | The receipt is signed over the ciphertext. Decrypting doesn't change the signature. |
| **Private key is separate** | The Ed25519 signing key and the X25519 forensic key are completely independent. Signing-key holders cannot decrypt; forensic-key holders cannot forge receipts. |

## Threat model

- **In transit:** Parameters are encrypted end-to-end. The receipt is signed, so any tampering is detected.
- **At rest:** The encrypted parameters sit in your audit store. Without the forensic private key, they're ciphertext.
- **Forensic recovery:** Only the holder of the forensic private key can decrypt. This can be a separate person, team, or HSM.
- **Plaintext window:** Between "receive parameters" and "encrypt", the emitter briefly holds plaintext. Daemon mode (coming in #280) moves this window out of the agent process.

## Why this matters

1. **You can audit high-risk commands without exposing secrets.** Store the plaintext of `"api_key": "sk-..."` encrypted, not in plaintext.
2. **Your storage stays pluggable.** SQLite, Postgres, S3 — all see the same signed receipt. The storage adapter never needs to know about encryption.
3. **SIEM/telemetry fan-out works.** Send the receipt to a SIEM. The SIEM sees hashes, action types, risk levels, timing, decisions — never the plaintext. Only the forensic responder with the private key can decrypt.
4. **Different personas, same architecture:**
   - **Solo dev:** Generate keypair once, store on the same machine.
   - **Team:** Public key in config, private key with a security lead.
   - **Enterprise:** Public key in images, private key in an HSM with multi-party approval.

## Current limitations (as of 2026-05-21)

- **Daemon wiring:** The daemon's `--parameter-disclosure` flag is a no-op. The daemon doesn't encrypt yet — tracked in #280. **SDK-direct mode works today.**
- **Key management CLI:** No `mcp-proxy inspect --decrypt` CLI yet. You decrypt by calling `DecryptDisclosure` in code.
- **OpenClaw integration:** The OpenClaw plugin's `parameterDisclosure` config maps to the TS SDK's builder (not the daemon). Works in OpenClaw, not yet in daemon.

## Next: automate this in your emitter

Pick your runtime:

- **Go:** Wire `EncryptDisclosure` into your tool harness. Load the public key from an env var or config.
- **TypeScript:** `encryptDisclosure()` is exported from `@agnt-rcpt/sdk-ts`. Wire it into your MCP server or agent plugin.
- **Python:** `agent_receipts.receipt.EncryptDisclosure` in the Python SDK. Same pattern.

Once the daemon wiring lands (#280), you'll set `parameterDisclosure: true` (or `"high"`) in daemon config and the encryption happens automatically — no code change needed.

## Testing locally

```bash
cd sdk/go
go test ./receipt -run TestDisclosure -v  # confirms the crypto works
```

All three SDKs have byte-identical test vectors in `spec/test-vectors/disclosure-envelope/vectors.json`.
