# ADR-0017: Central Receipt Hub and External Anchoring

## Status

Proposed

## Context

Multi-node deployments are now the common case: a personal laptop, EC2 instances running OpenClaw, EC2 instances running Hermes. Each node runs an `agent-receipts` daemon (per [ADR-0010](./0010-daemon-process-separation.md)) with its own Ed25519 key (per [ADR-0001](./0001-ed25519-for-receipt-signing.md)) and its own local SQLite chain (per [ADR-0004](./0004-sqlite-for-local-receipt-storage.md)). There is no aggregation point. An auditor who wants a unified view today walks N hosts, collects N databases, and verifies N independent chains by hand.

[ADR-0015](./0015-key-rotation-byok-anchoring.md) commits to external anchoring being load-bearing for the post-compromise integrity claim, but defines only the *write contract* — `Write(event_type, payload bytes) → error` to an append-only sink — not who calls it, where checkpoints aggregate from, or what the operator deploys. Multi-node operation pushes both problems together: the hub that aggregates chains is the natural place to emit checkpoints, and the anchor sink is what keeps the hub honest about what it has aggregated.

This ADR specifies the hub and pins ADR-0015's anchoring to a concrete deployment shape.

## Decision

Introduce a central hub that receives signed receipt batches from nodes over HTTPS, persists per-node chains, and periodically anchors per-node chain heads to an external append-only sink. The reference sink is an S3 bucket with object lock; the contract is the one in ADR-0015.

The hub is a deployment mode of the existing daemon, not a new component.

### 1. Local chain is the source of truth

The invariant everything else hangs off: each node's local SQLite chain is authoritative. The hub is a durable mirror. The integrity guarantee for any individual receipt does not depend on hub availability, hub correctness, or hub honesty.

A node whose hub is unreachable continues to sign, chain, and persist locally. A hub that is compromised cannot retroactively forge a receipt the local node already signed, because the node's chain still exists and still verifies under the node's DID. The hub adds aggregation and anchoring; it does not become a new trust root.

This invariant is the load-bearing premise for the rest of the ADR. Anything that would dissolve it — a hub-side re-signing step, a merged chain that replaces per-node chains, a transport that loses receipts the local node thinks it shipped — is rejected.

### 2. Transport: HTTPS POST with JSONL batches

Endpoint: `POST /v1/receipts`. Body: a JSONL batch of receipts, one canonicalised receipt per line (per [ADR-0002](./0002-rfc8785-json-canonicalization.md) and [ADR-0009](./0009-canonicalization-and-schema-consistency.md)), wrapped in a single JWS over the concatenated batch (see §4).

Batch policy: a shipper goroutine on each node flushes every 5s or every 100 receipts, whichever comes first. Both knobs are tunable; the defaults are sized for human-scale agent traffic, not telemetry-scale firehoses.

UDP is rejected. Loss on UDP is permanent divergence between the local chain (which has the receipt) and the hub (which does not), and the volume here is human-scale — there is no throughput problem UDP would solve. gRPC is rejected as the default for the same reason TCP loopback was rejected in ADR-0010: HTTPS is firewall- and NAT-friendly, every operator already runs an HTTPS reverse proxy, and a JSONL POST is trivially debuggable with `curl`. gRPC remains an option a future ADR can add if a high-throughput deployment ever needs streaming, but it is not the default.

### 3. Terminology: JSONL

Fix the project-wide term here. NDJSON, JSONL, and LDJSON all refer to the same format: one JSON value per line, `\n`-delimited, no enclosing array. Standardise on **JSONL** in code, configuration, documentation, and CLI flags. The spec lineage is [ndjson.org](https://github.com/ndjson/ndjson-spec) — JSONL is the same wire format with the more widely recognised name.

Rationale for picking JSONL over NDJSON: current usage in the broader ecosystem (jq, DuckDB, the LLM-eval ecosystem, log shippers) has settled on JSONL. NDJSON was the better name in 2014; JSONL is the better name in 2026. Picking one and using it everywhere is more important than which one.

This is a project-wide rename; see *Consequences* for the follow-up sweep.

### 4. Auth: reuse the daemon's Ed25519 key via JWS

The node signs each batch with a JWS (JSON Web Signature, [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) using EdDSA over the node's existing daemon key. The JWS is sent in the `Authorization: Bearer <jws>` header; the payload is the SHA-256 of the JSONL batch body, so the wire form is a compact JWS with a small fixed-size payload regardless of batch size. The hub verifies the JWS against its trust store — a list of authorised node DIDs — and rejects unknown signers.

No new credentials. No API keys. No separate transport PKI. The same key that signs every receipt signs the batch that carries them; the hub's authorisation decision uses the same DID resolution path (per [ADR-0007](./0007-did-method-strategy.md)) the verifier already uses.

**JWS chosen over HTTP Message Signatures (RFC 9421)** because:

- JWS is a self-contained, transport-independent artifact. The hub can persist the JWS alongside the batch for later forensic verification; an operator replaying a batch from disk gets the same signature surface as the original POST. RFC 9421 signs the HTTP request itself (selected headers plus the message body via a content digest) — useful for end-to-end HTTP integrity, but the artifact dies with the request.
- JWS aligns with the existing receipt envelope: [ADR-0003](./0003-w3c-vc-envelope-format.md) (W3C VC) already places us in the JOSE/JWS world. Adding RFC 9421 introduces a second signature framework for the same key for no integrity benefit.
- EdDSA-over-Ed25519 is a single-line JWS header (`{"alg":"EdDSA"}`) that every JOSE library implements; RFC 9421's signature-input/signature-params machinery is more surface area for the same one-key, one-algorithm use case.

RFC 9421 remains a reasonable option *in addition to* JWS if a future deployment puts the hub behind an HTTP-aware gateway that wants to attest the transport hop. It is not the default.

### 5. Per-node chains preserved at the hub — no merged chain

The hub verifies each receipt's chain links and stores it under the node's DID. There is one logical chain per node DID, mirroring exactly what each node holds locally. No hub-side `seq` allocator. No Merkle root across nodes. No cross-node ordering.

This is a deliberate **non-decision** so it is not relitigated: global ordering across nodes is *not* in scope for v1, and any future "global chain" proposal — Merkle accumulator across node tips, a hub-issued meta-receipt that commits to a set of node-chain tips, anything that would let an auditor ask "what happened across the fleet between T1 and T2 in causal order" — is a future ADR's problem. The reason: a merged chain requires the hub to be in the signing path or in the ordering path, which dissolves the invariant in §1.

Per-node chains aggregate without ordering. That is enough for v1.

### 6. Hub is `agent-receipts daemon --ingest`, not a separate binary

The hub runs the existing daemon with `--ingest` mode set. Same binary, same schema, same verifier, same `KeySource` (per ADR-0015), same storage. The hub dogfoods the architecture it serves.

Differences in `--ingest` mode versus default:

- **Listens on HTTPS** for `POST /v1/receipts` in addition to (or instead of) the local UDS in default mode. Operators choosing "hub-only" disable the UDS listener; operators running a node-that-is-also-the-hub keep both.
- **Verifies inbound batches** (JWS over batch payload, chain link verification per receipt, DID authorisation) before persisting. The default daemon's input is trusted local IPC (per ADR-0010); ingest input is untrusted network.
- **Owns the anchor schedule** (see §7). Default daemons do not anchor; only the hub does.
- **Holds a configured trust list** of authorised node DIDs. Default daemons do not — they only know their own key.

Same storage layout (SQLite per ADR-0004, one logical chain per node DID), same canonicalisation, same signature scheme. A future operator who wants to verify a hub-stored chain uses the same `agent-receipts verify` CLI against the hub's database that they would use against a node's database.

### 7. External anchoring: S3 with object lock for per-node chain heads

The hub periodically writes per-node chain heads to an S3 bucket with object lock enabled. Each anchor write is a `checkpoint` event as defined by ADR-0015: `(issuer.id, seq, tip_hash, public_key_fingerprint)`, RFC 8785-canonicalised, signed by the hub's own daemon key, written via the ADR-0015 `Write(event_type, payload bytes) → error` contract.

S3 object lock provides the two properties ADR-0015 demands of a sink:

- **Append-only retention.** Object lock in compliance mode makes objects immutable for the configured retention period; a compromised hub cannot rewrite or delete previously-written checkpoints.
- **Sink-controlled ordering and timestamps.** S3 stamps `LastModified` server-side and assigns version IDs in receipt order. The hub does not choose where its checkpoint lands or when S3 records it.

The S3 bucket — not the hub — is the trust root for the anchoring claim. Hub compromise is bounded: the attacker controls future receipts and future anchors but cannot rewrite previously-anchored checkpoints, so a verifier with S3 read access can detect any divergence between the hub's current view of a chain and the most recent anchored tip. State explicitly: the integrity property survives total hub compromise as long as the S3 bucket's object-lock configuration was set before the compromise and the attacker did not also compromise the AWS account holding the bucket.

Anchor frequency proposal: per node, the more recent of (a) every 5 minutes of wall clock during which receipts were ingested, or (b) every 1000 receipts ingested. Quiet nodes do not generate empty anchors; busy nodes do not let the detection window grow unbounded. Both knobs are tunable; both have direct cost/coverage tradeoffs (see *Open Questions*).

### 8. Scope: single-tenant for v1

One operator. One curated list of authorised node DIDs. One S3 bucket. The hub is sized for a small fleet under one administrative boundary — the laptop-plus-EC2 shape that motivates this ADR.

Multi-tenant deployment — per-tenant DID scoping, per-tenant S3 buckets, quotas, isolation between tenants, a UI to manage trust lists — is **deferred to a later ADR**. Recording it here explicitly so the door is left open and the v1 single-tenant assumption is not load-bearing for the integrity model: nothing in §1–§7 requires single-tenancy; the deferral is purely about operator surface.

## Architecture

```
emitters (openclaw / hermes / mcp-proxy)
   ↓ UDS SOCK_STREAM (JSONL, per ADR-0010)
local agent-receipts daemon
   ├─ canonicalize / sign / hash-chain
   ├─ persist to local SQLite (source of truth)
   └─ shipper goroutine
         ↓ HTTPS POST /v1/receipts (JWS-signed JSONL batch)
hub agent-receipts daemon (--ingest mode)
   ├─ verify batch JWS against known node DIDs
   ├─ re-verify each receipt's chain links
   └─ persist per-node chains to SQLite
         ↓ periodic anchor job
   S3 bucket with object lock (per-node chain heads, signed by hub)
```

## Consequences

### Positive

- Multi-node deployments get aggregation without surrendering per-node integrity. An auditor queries one hub instead of N hosts; verification still runs against per-node DIDs.
- ADR-0015's anchoring commitment gets a concrete reference implementation. The "load-bearing external sink" stops being aspirational.
- The hub adds no new trust root. Existing chain-verification tooling works against the hub's database with no protocol change.
- Reusing the daemon's signing key for transport auth means there is one credential to rotate, one DID to manage, one set of key-rotation semantics (ADR-0015 carries through).

### Negative / explicitly accepted

- **New failure mode: shipper crash or hub outage.** Local persistence absorbs the shipper crash (the receipt is still in SQLite; the shipper retries on restart). Hub outage is handled by exponential backoff retry in the shipper. Integrity is unaffected in either case — the local chain still verifies; the hub catches up when reachable. Worst case: the hub's view of a chain lags the node's by the outage duration.
- **Hub operator inherits a key-management responsibility.** The hub signs its own checkpoints, so it has a `KeySource` of its own. Slots into ADR-0015's BYOK abstraction unchanged — a hub operator can put the hub's key in KMS the same way a node operator can.
- **TLS in transit is table stakes; end-to-end encryption is not the integrity story.** Receipts are signed at the node; tampering at the hub is detectable by re-verifying signatures against the node DID. TLS protects confidentiality on the wire from passive observers; it is not where the integrity guarantee lives. *However*, if the redaction policy (per [ADR-0012](./0012-payload-disclosure-policy.md)) ever permits raw payloads through the chain, hub-side KMS encryption at rest or true E2E becomes interesting — flag for future work. This ADR assumes the redaction policy holds.
- **Transport-layer auth (mTLS, Tailscale, WireGuard) is defence-in-depth, not the integrity guarantee.** Out of scope for v1. Mentioned for operators with stricter network posture: nothing in this ADR prevents running the HTTPS endpoint behind a WireGuard mesh or mTLS gateway. The JWS auth still applies on top.
- **Terminology rename (NDJSON → JSONL) is a project-wide sweep.** Documentation, code comments, CLI help text, and any config field names referring to NDJSON change to JSONL. Track as a separate cleanup issue; no behaviour change.
- **Hub adds an installable component.** ADR-0010 already obliged operators to install a service-managed daemon; the hub is an additional deployment of the same binary. Packaging burden is incremental, not new.

## Alternatives considered

- **UDP transport.** A datagram per receipt or per batch. Rejected: UDP loss is permanent divergence between the local chain (which has the receipt) and the hub (which does not), and the throughput case that would justify UDP does not exist at human-scale agent traffic. Loss cost is permanent; benefit is zero.

- **gRPC streaming as the default.** Bidirectional streaming, schema-typed payloads, built-in flow control. Rejected as a default: gRPC is harder to expose through corporate firewalls and reverse proxies, harder to debug with off-the-shelf tools, and brings a schema-compiler dependency to every SDK for no integrity benefit at this scale. Reasonable as a future addition for a high-throughput deployment; not the default.

- **Merged global chain at the hub.** A hub-side `seq` allocator and a single chain across all nodes. Rejected: requires the hub to be in the signing or ordering path, dissolving the §1 invariant. Per-node chains preserve the integrity guarantee under hub compromise; a merged chain does not.

- **Separate hub binary.** A dedicated `agent-receipts-hub` distinct from the daemon. Rejected: same schema, same verifier, same storage, same canonicalisation, same key-management story — splitting the binary doubles the maintenance surface for no functional reason. Dogfooding the daemon as the hub also means every bug in one is exercised in the other.

- **New API-key credential instead of reusing the daemon key.** Hub-issued bearer tokens or operator-issued API keys. Rejected: introduces a second secret per node, a second rotation story, a second compromise surface. The daemon's Ed25519 key is already the node's strongest authentication primitive; using it for transport auth via JWS reuses what is already there.

- **Hub as trust root (no external anchoring).** Drop the S3 anchor and treat the hub's local store as the authoritative aggregation point. Rejected: a hub compromise then has no external check, and ADR-0015's post-compromise integrity claim has no anchor to land on. The whole point of the sink is to be something the hub does not control.

## Open questions

- **JWS vs HTTP Message Signatures (RFC 9421).** Proposal above is JWS, justified in §4. Open for community input — primarily on whether deployments that put the hub behind an HTTP-aware gateway would prefer the gateway to sign at the HTTP layer rather than relaying a JWS. The two are not mutually exclusive; the question is the default.
- **Anchor frequency to S3.** Proposal above is per-node, the more recent of (a) every 5 minutes of activity or (b) every 1000 ingested receipts. Tradeoff: smaller cadence shrinks the truncation-detection window (the gap between a receipt's ingestion and its appearance in an anchored checkpoint) but raises S3 write volume and cost. Per-batch anchoring is the strongest guarantee and the most expensive; per-hour is the cheapest and leaves the longest invisible window. The 5min/1000 default is a midpoint; deployments with stricter posture shorten it.
- **Hub's own DID and key lifecycle.** The hub signs checkpoints, so it has its own DID and its own `KeySource`. Proposal: yes, the hub registers itself the same way nodes do — `did:web` for production, `did:key` for development (per ADR-0007) — and rotates via the same ADR-0015 rotation event chain. The hub's DID appears in its own trust list as the recognised signer of checkpoints, distinct from the node DIDs it authorises for ingest. Confirm and pin in the implementing PR.

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — same key signs receipts and the JWS-wrapped batch.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — wire format for batch payloads and anchor checkpoints.
- [ADR-0003 (W3C VC envelope)](./0003-w3c-vc-envelope-format.md) — places the protocol in the JOSE/JWS world; informs §4's JWS choice.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — hub uses the same store layout per node DID.
- [ADR-0007 (DID method strategy)](./0007-did-method-strategy.md) — `did:web` for hub-registered production nodes, `did:key` for laptops; same resolution path on the hub's authorisation side.
- [ADR-0009 (canonicalisation and schema consistency)](./0009-canonicalization-and-schema-consistency.md) — null-handling rules apply identically to anchor payloads.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — the substrate; the hub is the same daemon in `--ingest` mode.
- [ADR-0012 (payload disclosure policy)](./0012-payload-disclosure-policy.md) — informs the "TLS is not the integrity story" consequence and the future-work flag for hub-side encryption.
- [ADR-0015 (key rotation, BYOK, external anchoring)](./0015-key-rotation-byok-anchoring.md) — supplies the anchor write contract this ADR pins to S3 with object lock; co-evolves with this ADR. Currently Proposed.
