# ADR-0018: Signer Abstraction and Cloud-Agnostic KeyProvider Design

## Status

Proposed — supersedes a prior keypair management design (keypair management ADR not yet filed in this repository)

## Context

A prior design established that keypair management must support ephemeral compute
(Lambda, Cloud Run, Fargate) and long-lived compute (EC2, bare metal, VMs).
During design review it became clear that `KeyProvider` — which returns raw
key bytes — cannot model environments where the private key is never
extractable (KMS, HSM, TPM). A second abstraction is required.

Additionally, the prior design implied cloud-specific implementations would ship
inside the core SDK package. This would introduce transitive cloud SDK
dependencies into the core package, which is unacceptable.

## Decision

### Two interfaces, one in core

```typescript
// @agnt-rcpt/sdk-ts (core)

export interface KeyPair {
  publicKey: Uint8Array   // 32 bytes, Ed25519
  privateKey: Uint8Array  // 32 bytes, Ed25519
}

// For environments where key bytes are accessible locally
export interface KeyProvider {
  getKeyPair(): Promise<KeyPair>
}

// For environments where the private key is never extractable
export interface Signer {
  sign(message: Uint8Array): Promise<Uint8Array>
  getPublicKey(): Promise<Uint8Array>
}
```

`AgentReceiptsClient` accepts a `Signer`. `KeyProvider` is a convenience
abstraction; all built-in `KeyProvider` implementations wrap themselves
as a `Signer` using local key bytes. Cloud-specific and hardware-backed
implementations implement `Signer` directly and never expose a `KeyPair`.

### Built-in providers (ship in the core SDK package, zero external dependencies)

| Provider | Behaviour | Use case |
|---|---|---|
| `FileKeyProvider` | Reads keypair from a file path. Does not auto-generate in production mode (see known limitations). | Dev, long-lived compute with persistent volume |
| `EnvVarKeyProvider` | Reads `AGENTRECEIPTS_KEY` (base58-encoded key value). Shares the env var name with the daemon (`daemon/README.md`), which interprets the value as a file path; the SDK's `EnvVarKeyProvider` interprets it as the key value directly. The deployment picks the form appropriate to its consumer. | Lambda/Cloud Run baseline, CI |
| `InMemoryKeyProvider` | Caller supplies raw `KeyPair` bytes directly. No I/O. Makes no memory safety guarantees (see known limitations). | Tests, delegation target for external-fetch adapters |
| `GeneratingKeyProvider` | Generates a fresh keypair and delegates persistence to a backing `KeyProvider`. Throws if `AGENTRECEIPTS_PRODUCTION=true`. | Dev and bootstrap only |

### External adapters (user-land, separate packages)

Cloud-specific and hardware adapters are published as separate packages.
The core SDK package has zero knowledge of any cloud provider. Package
names below are TypeScript-flavoured; see the "Package boundaries" section
below for Python and Go equivalents.

| Package | Adapter | Interface | Notes |
|---|---|---|---|
| `@agnt-rcpt/sdk-ts-aws` | `SecretsManagerKeyProvider` | `KeyProvider` | Fetches from AWS Secrets Manager using instance role. Caches in-process (one fetch per cold start). Delegates to `InMemoryKeyProvider`. |
| `@agnt-rcpt/sdk-ts-aws` | `KMSSigner` | `Signer` | Signs via AWS KMS API. Private key never leaves KMS. |
| `@agnt-rcpt/sdk-ts-gcp` | `SecretManagerKeyProvider` | `KeyProvider` | GCP Secret Manager equivalent. |
| `@agnt-rcpt/sdk-ts-gcp` | `CloudKMSSigner` | `Signer` | GCP Cloud KMS equivalent. |
| `@agnt-rcpt/sdk-ts-tpm` | `TPMSigner` | `Signer` | TPM2 on Linux via tpm2-tss binding. Key generated inside TPM, never extractable. |
| user-land | any | `KeyProvider` or `Signer` | Implement either interface — no SDK changes required. |

### Package boundaries

The split between core and cloud adapters is itself a design decision, not
an incidental packaging choice. The principle: **the core SDK package has
zero cloud or hardware dependencies; every cloud or hardware adapter ships
as a separate, independently versioned unit.**

Each SDK implements this split in its language-idiomatic way:

| SDK | Core | AWS adapter | GCP adapter | TPM adapter |
|---|---|---|---|---|
| TypeScript | `@agnt-rcpt/sdk-ts` | `@agnt-rcpt/sdk-ts-aws` | `@agnt-rcpt/sdk-ts-gcp` | `@agnt-rcpt/sdk-ts-tpm` |
| Python | `agent-receipts` | `agent-receipts[aws]` | `agent-receipts[gcp]` | `agent-receipts[tpm]` |
| Go | `github.com/agent-receipts/ar/sdk/go` | `…/sdk/go/aws` (separate module) | `…/sdk/go/gcp` (separate module) | `…/sdk/go/tpm` (separate module) |

TypeScript adapter packages declare core as a `peerDependency` to guarantee
a single core copy at runtime. Each Go adapter is its own module (separate
`go.mod`), so a project that does not import the AWS adapter never pulls
the AWS SDK into its dependency closure — at the cost of independent
versioning across modules. Python extras pull in the cloud SDK only when
explicitly requested (`pip install agent-receipts[aws]`).

References throughout this ADR use TypeScript package names for
concreteness; the same packaging principle applies in each SDK's
idiomatic form.

### Recommended provider by deployment target

| Environment | Recommended | Interface |
|---|---|---|
| Dev / local | `FileKeyProvider` (auto-generate on first run permitted) | `KeyProvider` |
| CI / test | `InMemoryKeyProvider` (injected fixture keypair) | `KeyProvider` |
| Lambda / Cloud Run / Fargate | `EnvVarKeyProvider` or `SecretsManagerKeyProvider` | `KeyProvider` |
| EC2 / VM (baseline) | `FileKeyProvider` (chmod 600, OS keyring encryption at rest) | `KeyProvider` |
| EC2 / VM (better) | `SecretsManagerKeyProvider` (instance role as trust anchor) | `KeyProvider` |
| Bare metal / EC2 (best) | `TPMSigner` | `Signer` |
| KMS / HSM anywhere | `KMSSigner` or equivalent | `Signer` |

### Key generation policy

Key generation in production is a deliberate out-of-band operation, not
an automatic SDK behaviour. `GeneratingKeyProvider` is explicitly prohibited
in production environments (`AGENTRECEIPTS_PRODUCTION=true`). Production
deployments provision the keypair via their secret store and configure the
SDK to fetch it.

SDK environment variables use the `AGENTRECEIPTS_` prefix to match existing
project conventions (`AGENTRECEIPTS_SOCKET`, `AGENTRECEIPTS_KEY`,
`AGENTRECEIPTS_DB`, etc. — see `daemon/README.md`). `AGENTRECEIPTS_KEY` is
shared with the daemon by name; its value form depends on the consumer (file
path for the daemon and the SDK's `FileKeyProvider`; base58-encoded key
value for the SDK's `EnvVarKeyProvider`).

### Session continuity

The keypair must be stable within a session. The SDK validates on every
receipt emission that the signing DID matches the DID recorded in the
session's `agent_start` receipt. A mismatch throws `KeyMismatchError`
rather than silently producing an unverifiable chain.

Key rotation is not supported within an active session. Rotation requires
completing the current session (`agent_end`) and starting a new one with
`previousReceiptHash: null`.

### Identity scoping

One keypair per agent type per deployment stage. All instances of the same
logical agent in the same stage share a DID. This keeps audit trails
attributable to a logical agent rather than to an arbitrary compute instance.

## Consequences

- The core SDK package has zero cloud or hardware dependencies.
- Adding support for a new secret store or HSM requires no changes to core —
  implement `KeyProvider` or `Signer` and publish a separate package.
- KMS, HSM, and TPM deployments must implement `Signer`; `KeyProvider` alone
  cannot model environments where the private key is never extractable.
- Cross-SDK compatibility (TypeScript, Python, Go) requires equivalent
  built-in providers in each SDK and a shared conformance test suite
  (see ADR-0019).

## Known limitations

- `InMemoryKeyProvider` holds private key bytes as plain heap memory. No
  memory safety guarantees. See issue #485.
- `did:key` has no revocation mechanism. Key compromise requires out-of-band
  notification and a new agent identity. See issue #483.
- Timestamp binding is self-reported. See ADR-0019 and issue #482.

## Related ADRs

- ADR-0019 — Protocol integrity gaps and mitigations (depends on Signer)
- ADR-0020 — Emitter abstraction and remote receipt delivery (composes with
  Signer to support ephemeral compute end-to-end)
