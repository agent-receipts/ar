# ADR-0020: Emitter Abstraction and Remote Receipt Delivery

## Status

Proposed

## Context

The initial MCP proxy design assumes a long-lived daemon process (sidecar or
local socket) that handles signing, chaining, and storage on behalf of the
agent. This works for long-lived compute but fails entirely in ephemeral
environments (Lambda, Cloud Run, Fargate) where there is no persistent process
between invocations. There is no sidecar to connect to, and a Lambda Extension
— while technically feasible — is runtime-specific, adds cold start latency,
and requires a compiled binary bundled with every deployment.

A secondary concern: the MCP proxy design conflates three responsibilities —
receipt construction, signing/chaining, and delivery. These should be
separable.

Two options were evaluated:

**Option A — Lambda Extension.** A sidecar process registered with the Lambda
Runtime API, surviving between warm invocations. Holds keypair in memory,
handles signing and chaining, forwards to the receipt store. Discarded: too
runtime-specific, operational overhead disproportionate to the benefit, and
does not generalise to Cloud Run, Fargate, or bare metal.

**Option B — Remote emitter over HTTPS.** The SDK emits completed, signed,
chained receipts directly to a remote collector endpoint over HTTPS. No local
daemon. The collector receives already-signed receipts and stores them — it has
no role in chain construction. Adopted.

## Decision

### Emitter interface

A new `Emitter` interface is added to the core SDK package (`@agnt-rcpt/sdk-ts` and equivalents — see ADR-0018 § "Package boundaries"):

```typescript
interface Emitter {
  emit(receipt: SignedReceipt): Promise<void>
}
```

Receipt construction, signing, and chaining remain client-side in all cases.
The `Emitter` is responsible only for delivery. The collector is a dumb store —
it receives complete, signed, already-chained receipts and persists them. It
has no role in sequencing, hashing, or signing, and is therefore not a trusted
component in chain construction.

This preserves the core trust model: an auditor needs only the agent's public
key to verify the entire chain. The collector cannot fabricate or alter
receipts.

### Built-in emitters (ship in the core SDK package)

#### `HttpEmitter`

Posts signed receipts to a remote HTTPS endpoint. Suitable for all deployment
targets including ephemeral compute.

```typescript
interface HttpEmitterConfig {
  endpoint: string
  auth?: HttpEmitterAuth
  strategy?: 'sync' | 'fire-and-forget'
  retry?: RetryConfig
  timeoutMs?: number
}

type HttpEmitterAuth =
  | { type: 'api-key'; header: string; value: string }
  | { type: 'bearer'; token: string }
  | { type: 'mtls'; cert: Uint8Array; key: Uint8Array }
  | { type: 'none' }
```

`strategy`:
- `sync` (default) — `emit()` resolves when the collector acknowledges.
  Provides at-least-once delivery. Recommended for production.
- `fire-and-forget` — `emit()` resolves immediately after dispatch. No
  delivery guarantee. Acceptable for high-throughput workloads where
  occasional receipt loss is tolerable and latency matters.

#### `DaemonEmitter`

Sends receipts to a local daemon over a Unix socket or named pipe. Existing
behaviour for long-lived compute deployments with a sidecar. Retained as a
built-in for backwards compatibility.

#### `CompositeEmitter`

Forwards each receipt to multiple emitters in sequence. Useful for dual-write
during migration (daemon + HTTP), or for writing to both a local store and a
remote collector simultaneously.

```typescript
new CompositeEmitter([daemonEmitter, httpEmitter])
```

#### `BufferingEmitter`

Wraps another emitter and buffers receipts in memory, flushing on a configurable
interval or batch size. Useful for high-throughput agents where per-receipt HTTP
round-trips are cost-prohibitive. Note: buffered receipts are lost if the
process crashes before flush. Not recommended where audit completeness is
critical.

#### `InMemoryEmitter`

Holds received receipts in an exposed in-memory array for inspection. Used
as a test double in unit and integration tests. Performs no I/O and provides
no delivery guarantee — assertion against captured receipts is the entire
point. Not for production use.

### Recommended emitter by deployment target

| Environment | Recommended emitter | Notes |
|---|---|---|
| Dev / local | `DaemonEmitter` or `HttpEmitter` (localhost) | Local daemon or local collector |
| CI / test | `InMemoryEmitter` (test double) | No I/O, assertions on emitted receipts |
| Lambda / Cloud Run / Fargate | `HttpEmitter` (sync) | Only viable option; collector must be reachable from the function VPC |
| EC2 / VM | `DaemonEmitter` or `HttpEmitter` | Either works; daemon preferred if sidecar already present |
| Bare metal | `DaemonEmitter` or `HttpEmitter` | As above |

### Collector contract

The collector exposes a single endpoint:

```
POST /receipts
Content-Type: application/ld+json

{ ...signedReceipt }

→ 201 Created   (receipt accepted and persisted)
→ 409 Conflict  (receipt id already exists — idempotent re-delivery acceptable)
→ 400 Bad Request (malformed receipt — SDK should not retry)
→ 5xx           (transient error — SDK should retry with backoff)
```

The collector MUST NOT:
- Modify receipts
- Reorder receipts
- Assign or recompute `previousReceiptHash`
- Reject receipts solely on the basis of signature verification failure
  (verification is the auditor's responsibility, not the collector's)

The collector SHOULD:
- Be append-only
- Return 409 on duplicate `id` rather than 500, to support safe retry

### Concurrency constraint

Client-side chaining requires that receipt N is fully signed and its hash
computed before receipt N+1 is constructed. This is naturally satisfied for
sequential single-process agents. For agents that emit receipts concurrently
(e.g. parallel tool calls), the SDK must serialise receipt construction through
a queue. Concurrent signing and emission of independent receipts is not
supported in v1 — parallel tool calls must be sequenced at the receipt layer
even if they execute in parallel.

This constraint should be documented explicitly. A future ADR may address
parallel sub-chains (forked chains with a merge receipt) for v2.

### At-least-once delivery and the WAL

For `sync` strategy, the SDK retries on 5xx with exponential backoff and jitter
up to a configurable limit. If the retry budget is exhausted, `emit()` throws
`EmitError`. The caller (SDK internals) should write the receipt to a local WAL
before attempting delivery, and clear the WAL entry on 201 or 409. On process
restart, unacknowledged WAL entries are replayed.

For ephemeral compute (Lambda) a WAL on disk is not viable. In this case:
- The WAL is in-memory only
- On SIGTERM the SDK attempts a final flush with a short deadline
- Any undelivered receipts are lost; the chain will show a gap
- This should be surfaced as `status: interrupted` on the `agent_end` receipt
  per ADR-0019 § P1

### Interaction with ADR-0018 (Signer) and ADR-0019 (integrity gaps)

The `Emitter` abstraction does not affect signing or chaining. The full
pipeline remains:

```
event occurs
  → SDK constructs receipt payload
  → Signer signs (local bytes, KMS, TPM — per ADR-0018)
  → previousReceiptHash computed from prior signed receipt
  → SignedReceipt complete
  → Emitter.emit(signedReceipt)
    → HttpEmitter POSTs to collector  (or DaemonEmitter sends to sidecar)
```

The collector is downstream of all cryptographic operations.

The WAL requirement in this ADR supersedes the MCP proxy WAL requirement
in ADR-0019 § O3. The WAL now lives in the SDK emitter layer, not in the
proxy, making it available regardless of whether the MCP proxy is in use.

## Consequences

> For the consolidated v1 / v2 sequencing across this ADR and ADR-0018/0019,
> see `ROADMAP.md`.

- The SDK gains a required `Emitter` dependency at construction time alongside
  `Signer` and `KeyProvider`.
- Ephemeral compute is fully supported without any runtime-specific extensions
  or sidecars.
- The collector is a dumb append-only store. No business logic. No trust
  assumptions.
- Concurrent parallel tool calls must be sequenced at the receipt layer in v1.
  This is a known constraint, not a bug.
- `DaemonEmitter` is retained. Existing deployments are unaffected.
- ADR-0019 § O3 (MCP proxy WAL) is superseded by the SDK-layer WAL defined here.

## Known limitations

- In-memory WAL only for ephemeral compute. Receipt loss on hard crash or
  timeout is possible. Surfaced as `status: interrupted`.
- `fire-and-forget` strategy provides no delivery guarantee. Caller accepts
  the risk.
- Parallel sub-chains not supported in v1. Sequential receipt construction
  is required.
- `BufferingEmitter` is not suitable where audit completeness is critical.
  Loss on crash is documented but easy to misconfigure.
