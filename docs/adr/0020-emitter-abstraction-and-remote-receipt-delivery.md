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
  emit(receipt: AgentReceipt): Promise<void>
}
```

`AgentReceipt` is the existing signed-receipt type defined in the core SDK
(`sdk/ts/src/receipt/types.ts` and equivalents in Go and Python) — the
W3C VC envelope with a required `proof` field. The unsigned variant is
`UnsignedAgentReceipt = Omit<AgentReceipt, "proof">`. Emitters receive
already-signed receipts; signing is upstream.

Receipt construction, signing, and chaining remain client-side in all cases.
The `Emitter` is responsible only for delivery. The collector is a dumb store —
it receives complete, signed, already-chained receipts and persists them. It
has no role in sequencing, hashing, or signing, and is therefore not a trusted
component in chain construction.

This preserves the core trust model: an auditor needs only the agent's public
key to verify the entire chain. The collector cannot fabricate or alter
receipts.

> **Note on naming.** The TypeScript SDK already exports an `Emitter` class
> in `sdk/ts/src/emitter.ts` that forwards *unsigned* tool-call event frames
> over a Unix socket to the agent-receipts daemon, where signing and chaining
> happen (per ADR-0010). That class is renamed to `DaemonEmitter` as part of
> this work; the name `Emitter` is freed up for the new interface defined
> here. See § "Migration from the current daemon architecture" below.

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

Sends receipts to a local daemon over a Unix socket or named pipe. Retained
as a built-in for deployments that already run the agent-receipts daemon
as a sidecar.

`DaemonEmitter`'s relationship to the new client-side signing model is not
trivial — see § "Migration from the current daemon architecture" below.
Until the daemon grows a signed-receipt ingest mode, `DaemonEmitter` keeps
the existing unsigned-frame protocol from ADR-0010 and does not yet conform
to the `Emitter` interface defined above.

#### `CompositeEmitter`

Forwards each receipt to multiple emitters in sequence. Useful for writing
to two collectors simultaneously (e.g. a primary endpoint plus an offsite
audit archive) or for dual-writing during a migration between endpoints.

```typescript
new CompositeEmitter([primaryHttpEmitter, archiveHttpEmitter])
```

`CompositeEmitter` requires every child to implement the `Emitter` interface
defined above. `DaemonEmitter` does not yet (see § "Migration from the
current daemon architecture"); the daemon → HTTP dual-write pattern becomes
available once step 2 of the migration lands.

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

{ ...agentReceipt }

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

### Migration from the current daemon architecture

ADR-0010 placed signing and chaining in the daemon and modelled the SDK as
a thin emitter of *unsigned* tool-call frames. ADR-0020 inverts that —
signing and chaining are client-side, the receiver is a dumb store. The
existing daemon path is not obsolete (sidecar deployments remain useful for
storage, redaction, and local audit query), but its protocol no longer
matches the new `Emitter` interface. The migration has two steps.

**Step 1 — rename the existing TS class.** `sdk/ts/src/emitter.ts` currently
exports `Emitter` (unsigned `EmitEvent` frames, daemon signs). That class is
renamed to `DaemonEmitter` with no behaviour change. Its `emit()` method
keeps its current signature — it does not yet take `AgentReceipt`. Existing
callers update the import name; the wire protocol with the daemon is
unchanged. Python and Go SDKs that grow equivalent helpers follow the same
rename rule.

**Step 2 — daemon learns to accept signed receipts.** A new frame type is
added to the daemon socket protocol that carries an already-signed,
already-chained receipt for storage only (no signing on the daemon side).
Once the daemon understands this frame, `DaemonEmitter` gains an
`emit(AgentReceipt)` overload that uses it, and at that point
`DaemonEmitter` implements the `Emitter` interface defined in this ADR.
Until then `DaemonEmitter` exists as a legacy adapter with a different
input shape, and is not interchangeable with `HttpEmitter` in
`CompositeEmitter`.

Step 1 is mechanical and ships with this ADR's implementation work
(SDK emitter layer milestone in ROADMAP.md). Step 2 is daemon-side work
tracked separately — it does not block ADR-0020's primary goal, which is
ephemeral-compute support via `HttpEmitter`.

### Interaction with ADR-0018 (Signer) and ADR-0019 (integrity gaps)

The `Emitter` abstraction does not affect signing or chaining. The full
pipeline remains:

```
event occurs
  → SDK constructs receipt payload
  → Signer signs (local bytes, KMS, TPM — per ADR-0018)
  → previousReceiptHash computed from prior signed receipt
  → AgentReceipt complete
  → Emitter.emit(agentReceipt)
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
