# Agent Receipts — AWS adapter (Go)

`github.com/agent-receipts/ar/sdk/go/aws`

This module is the AWS KMS implementation of the Agent Receipts **`Signer`**
abstraction from [ADR-0018](../../../docs/adr/0018-signer-abstraction-and-cloud-agnostic-keyprovider-design.md).
`KMSSigner` signs receipts with an Ed25519 key whose private half **never
leaves AWS KMS** — the adapter holds only a key identifier and an in-memory
copy of the public key.

It ships as a **separate Go module** so the core `sdk/go` package keeps zero
AWS dependencies. A project that does not import this module never pulls the
AWS SDK into its dependency closure.

Use it for ephemeral compute (Lambda, Fargate, EKS) where raw
key bytes from env/SSM/Secrets Manager are unacceptable and full CloudHSM /
PKCS#11 is overkill.

## Install

```sh
go get github.com/agent-receipts/ar/sdk/go/aws
```

Requires Go 1.26+. Authentication uses the ambient AWS SDK credential chain
(instance role, IRSA, environment, shared profile) — the adapter never accepts
static credentials.

## Provisioning an Ed25519 KMS key

AWS KMS added Ed25519 (EdDSA) support in November 2025. The key spec is
**`ECC_NIST_EDWARDS25519`** with key usage `SIGN_VERIFY`:

```sh
aws kms create-key \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description "agent-receipts signing key (prod)"

# Optional: a stable alias so deployments reference alias/... not a raw key ID.
aws kms create-alias \
  --alias-name alias/agent-receipts-prod \
  --target-key-id <key-id-from-create-key>
```

> **Note on signing parameters.** The adapter calls `kms:Sign` with
> `SigningAlgorithm=ED25519_SHA_512` and `MessageType=RAW`. That combination is
> standard (pure) Ed25519 per RFC 8032 — KMS performs the SHA-512 hash
> internally — so signatures verify with Go's `crypto/ed25519.Verify` and
> across the TypeScript and Python SDKs. (`ED25519_PH_SHA_512` is the
> pre-hashed variant and is **not** used here.)

`KMSSigner.GetPublicKey()` returns the raw 32-byte Ed25519 public key (RFC 8032
§5.1.5), decoded from the DER-encoded SPKI that `kms:GetPublicKey` returns.

## IAM permissions

The execution role (Lambda role, instance profile, IRSA service account) needs
exactly two KMS actions on the signing key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AgentReceiptsSign",
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey"],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/<key-id>"
    }
  ]
}
```

No `kms:CreateKey`, `kms:Decrypt`, or key-policy changes are required at
runtime.

## Usage

```go
ctx := context.Background()

// Imported as awssigner to avoid colliding with github.com/aws/aws-sdk-go-v2/aws.
// keyID is a key ID, key ARN, alias name (alias/...), or alias ARN.
signer, err := awssigner.NewKMSSigner(ctx, "alias/agent-receipts-prod",
    awssigner.WithTimeout(10*time.Second))
if err != nil {
    log.Fatal(err)
}

sig, err := signer.Sign(canonicalReceiptBytes) // raw 64-byte Ed25519 signature
pub, err := signer.GetPublicKey()              // raw 32-byte Ed25519 public key
```

`GetPublicKey` contacts KMS only on the first call and caches the result for
the signer's lifetime; later calls return the cached key. AWS SDK errors from
`Sign`/`GetPublicKey` are wrapped with operation context but preserve the
underlying error via `%w`, so callers can still `errors.As` them to distinguish
throttling, access-denied, and key-not-found. The adapter adds **no** retry
layer of its own — `aws-sdk-go-v2` already retries.

### End-to-end: sign a receipt and emit it via `HttpEmitter`

This wires `KMSSigner` to the core SDK's receipt builder and the
[`HttpEmitter`](../emitters/http.go) collector transport. The core `sdk/go`
package does not yet expose a `Signer`-accepting `Sign` helper (it signs from
PEM bytes), so the few lines that turn a remote signature into a `proof` are
shown inline; see the follow-up note below.

```go
package main

import (
    "context"
    "encoding/base64"
    "log"
    "time"

    awssigner "github.com/agent-receipts/ar/sdk/go/aws"
    "github.com/agent-receipts/ar/sdk/go/emitters"
    "github.com/agent-receipts/ar/sdk/go/receipt"
)

func main() {
    ctx := context.Background()

    // 1. Remote signer — private key stays in KMS.
    signer, err := awssigner.NewKMSSigner(ctx, "alias/agent-receipts-prod",
        awssigner.WithTimeout(10*time.Second))
    if err != nil {
        log.Fatal(err)
    }

    // verificationMethod is how verifiers look up the public key
    // (e.g. a did:key derived from signer.GetPublicKey(), or an https URL).
    const verificationMethod = "did:web:agents.example.com#key-1"

    // 2. Build an unsigned receipt.
    unsigned := receipt.Create(receipt.CreateInput{
        Issuer:    receipt.Issuer{ID: "did:web:agents.example.com", Name: "billing-agent"},
        Principal: receipt.Principal{ID: "user:42"},
        Action: receipt.Action{
            Type:      "tool_call",
            ToolName:  "issue_refund",
            RiskLevel: receipt.RiskHigh,
        },
        Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
        Chain:   receipt.Chain{Sequence: 0, ChainID: "chain-abc"},
    })

    // 3. Sign the canonical bytes in KMS and assemble the proof.
    canonical, err := receipt.Canonicalize(unsigned)
    if err != nil {
        log.Fatal(err)
    }
    sig, err := signer.Sign([]byte(canonical))
    if err != nil {
        log.Fatal(err) // raw AWS error: throttling / access-denied / not-found
    }
    signed := receipt.AgentReceipt{
        Context:           unsigned.Context,
        ID:                unsigned.ID,
        Type:              unsigned.Type,
        Version:           unsigned.Version,
        Issuer:            unsigned.Issuer,
        IssuanceDate:      unsigned.IssuanceDate,
        CredentialSubject: unsigned.CredentialSubject,
        Proof: receipt.Proof{
            Type:               receipt.ProofTypeEd25519Signature2020,
            Created:            time.Now().UTC().Format(time.RFC3339),
            VerificationMethod: verificationMethod,
            ProofPurpose:       "assertionMethod",
            // multibase "u" prefix + base64url(signature), per ADR-0001.
            ProofValue: "u" + base64.RawURLEncoding.EncodeToString(sig),
        },
    }

    // 4. Emit to the collector.
    emitter, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
        Endpoint: "https://collector.example.com/receipts",
        Auth:     emitters.BearerAuth{Token: "..."},
    })
    if err != nil {
        log.Fatal(err)
    }
    if err := emitter.Emit(ctx, signed); err != nil {
        log.Fatal(err)
    }
}
```

> **Follow-up.** A `Signer`-accepting `receipt.Sign` in core `sdk/go` would
> collapse step 3 to one call and remove the inline multibase encoding. That
> belongs in core, not this adapter (which must not modify core per #575), and
> is tracked as a follow-up.

## Limitations

- **Use a key ARN (or key ID) for production signing, not an alias.**
  `GetPublicKey` caches the public key on first use, but `Sign` always targets
  the live `keyID`. If `keyID` is an *alias* and the alias is repointed to a
  different key during the signer's lifetime, signatures are produced under the
  new key while the cached/published public key is the old one — so receipts
  fail verification. This fails closed (verifiers reject; no forged receipt is
  accepted), but a key ARN avoids the divergence entirely. Aliases remain fine
  for dev and for resolving the key once at startup.

- **Receipts must canonicalize to ≤ 4096 bytes.** `kms:Sign` with
  `MessageType=RAW` caps the message at 4096 bytes, and pure Ed25519
  (`ED25519_SHA_512`) cannot use the `DIGEST` pre-hash path. A receipt whose
  canonical form exceeds 4 KB — typically from large `parameters_disclosure`
  envelopes or long prompt previews — cannot be signed by this adapter, even
  though the core SDK signs arbitrary-length bytes locally. The call fails
  loudly with an AWS error (the audit gap is visible, never silent); keep
  disclosed payloads hashed rather than inlined to stay under the limit.

## Integration test

`integration_test.go` exercises a real KMS key and is **skipped unless**
`AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN` is set, so CI stays offline by
default. To run it locally against an `ECC_NIST_EDWARDS25519` key your ambient
credentials can `kms:Sign` / `kms:GetPublicKey`:

```sh
AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/<key-id> \
    go test ./... -run TestIntegration -v
```

The test fetches the public key, signs a message in KMS, and verifies the
signature locally with `crypto/ed25519` — proving the `ED25519_SHA_512` + `RAW`
parameters produce interoperable Ed25519 signatures.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .
go test ./...   # unit tests use a mocked KMS client; no network or credentials
```
