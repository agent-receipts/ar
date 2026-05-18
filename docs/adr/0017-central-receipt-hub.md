# ADR-0017: Central Receipt Hub and External Anchoring

## Status

Proposed. Implementation is gated on three Phase A's landing first — see *Preconditions* below. This ADR is intentionally kept in Proposed status until those clear; the design is concrete enough to review and build against, but the hub MUST NOT be deployed until the gate is closed.

## Context

Multi-node deployments are now the common case: a personal laptop, EC2 instances running OpenClaw, EC2 instances running Hermes. Each node runs an `agent-receipts` daemon (per [ADR-0010](./0010-daemon-process-separation.md)) with its own Ed25519 key (per [ADR-0001](./0001-ed25519-for-receipt-signing.md)) and its own local SQLite chain (per [ADR-0004](./0004-sqlite-for-local-receipt-storage.md)). There is no aggregation point. An auditor who wants a unified view today walks N hosts, collects N databases, and verifies N independent chains by hand.

[ADR-0015](./0015-key-rotation-byok-anchoring.md) commits to external anchoring being load-bearing for the post-compromise integrity claim, but defines only the *write contract* — `Write(event_type, payload bytes) → error` to an append-only sink — not who calls it, where checkpoints aggregate from, or what the operator deploys. Multi-node operation pushes both problems together: the hub that aggregates chains is the natural place to emit checkpoints, and the anchor sink is what keeps the hub honest about what it has aggregated.

This ADR specifies the hub and pins ADR-0015's anchoring to a concrete deployment shape.

## Preconditions

Hub implementation MUST NOT begin until each of the following has shipped. These are deliberate gates, not soft dependencies; building the hub against unstable foundations leaks the instability into the hub's wire format and re-verifier code.

1. **ADR-0007 Phase A — `did:key` resolution everywhere.** Daemon and all three SDKs ship `did:key` generation and resolution. The daemon's `did:user:unknown` placeholder in `daemon/internal/pipeline/build.go` is removed. The hub's JWS auth (§4) uses `kid` = node DID URL via DID resolution — there is no fallback. Without `did:key` shipped, the hub cannot authenticate any batch.

2. **ADR-0015 Phase A — complete.** `KeySource.Rotate()` implemented, rotation event schema pinned in canonical form (see ADR-0015 §"Wire-format placement"), file-backed anchor sink built, verifier-side rotation traversal landed. The hub uses the same `KeySource` for its own key and the same `Write` contract for its own checkpoints; partial Phase A means partial hub.

3. **ADR-0012 Phase A envelope — disclosure carries ciphertext, not plaintext.** The asymmetric envelope (`v`, `alg`, `recipients`, `nonce`, `ct`) is shipped in all three SDKs and the daemon's `--parameter-disclosure` flag is rewired from redacted-plaintext to envelope. This is the **user-facing gate**: hub aggregation is unsafe before this lands because any opt-in plaintext disclosure on a node becomes, post-aggregation, a concentrated secrets corpus on the hub — a materially worse blast radius than per-node plaintext, and one that no operational control on the hub can recover.

Cross-track spec PRs that should land before the implementation phases above start in earnest:

- `did:key` value shape and resolution algorithm, with cross-SDK test vectors.
- Rotation event canonical wire format (currently deferred in ADR-0015 itself).
- Disclosure envelope canonical shape, with cross-SDK byte-identical test vectors.

These are small, code-free PRs that derisk the three parallel implementation tracks.

## Decision

Introduce a central hub that receives signed receipt batches from nodes over HTTPS, persists per-node chains, and periodically anchors per-node chain heads to an external append-only sink. The reference sink is an S3 bucket with object lock; the contract is the one in ADR-0015.

The hub is a deployment mode of the existing daemon, not a new component.

### 1. Local chain is the source of truth

The invariant everything else hangs off: each node's local SQLite chain is authoritative. The hub is a durable mirror. The integrity guarantee for any individual receipt does not depend on hub availability, hub correctness, or hub honesty.

A node whose hub is unreachable continues to sign, chain, and persist locally. A hub that is compromised cannot retroactively forge a receipt the local node already signed, because the node's chain still exists and still verifies under the node's DID. The hub adds aggregation and anchoring; it does not become a new trust root *for receipts*. (For the anchoring claim specifically, the S3 bucket is the trust root — see §7. The hub is never the trust root for either receipts or anchors.)

This invariant is the load-bearing premise for the rest of the ADR. Anything that would dissolve it — a hub-side re-signing step, a merged chain that replaces per-node chains, a transport that loses receipts the local node thinks it shipped — is rejected.

### 2. Transport: HTTPS POST with JSONL batches

Endpoint: `POST /v1/receipts`. The HTTP body is the raw JSONL batch — one canonicalised receipt per line, per [ADR-0002](./0002-rfc8785-json-canonicalization.md) and [ADR-0009](./0009-canonicalization-and-schema-consistency.md). The batch is authenticated by a JWS carried in the `Authorization` header that signs a small claims object including a SHA-256 digest of the body; the JWS does not embed the body itself. Wire detail in §4.

Batch policy: a shipper goroutine on each node flushes every 5s or every 100 receipts, whichever comes first. Both knobs are tunable; the defaults are sized for human-scale agent traffic, not telemetry-scale firehoses.

UDP is rejected. Loss on UDP is permanent divergence between the local chain (which has the receipt) and the hub (which does not), and the volume here is human-scale — there is no throughput problem UDP would solve. gRPC is rejected as the default for the same reason TCP loopback was rejected in ADR-0010: HTTPS is firewall- and NAT-friendly, every operator already runs an HTTPS reverse proxy, and a JSONL POST is trivially debuggable with `curl`. gRPC remains an option a future ADR can add if a high-throughput deployment ever needs streaming, but it is not the default.

### 3. Terminology: JSONL

Fix the project-wide term here. NDJSON, JSONL, and LDJSON all refer to the same format: one JSON value per line, `\n`-delimited, no enclosing array. Standardise on **JSONL** in code, configuration, documentation, and CLI flags. The spec lineage is [ndjson.org](https://github.com/ndjson/ndjson-spec) — JSONL is the same wire format with the more widely recognised name.

Rationale for picking JSONL over NDJSON: current usage in the broader ecosystem (jq, DuckDB, the LLM-eval ecosystem, log shippers) has settled on JSONL. NDJSON was the better name in 2014; JSONL is the better name in 2026. Picking one and using it everywhere is more important than which one.

This is a project-wide rename; see *Consequences* for the follow-up sweep.

### 4. Auth: reuse the daemon's Ed25519 key via JWS

The node signs each batch with a JWS (JSON Web Signature, [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) using EdDSA over the node's existing daemon key. No new credentials. No API keys. No separate transport PKI. The same key that signs every receipt signs the batch that carries them; the hub's authorisation decision uses the same DID resolution path (per [ADR-0007](./0007-did-method-strategy.md)) the verifier already uses.

#### Wire shape

- **Compact JWS** carried in `Authorization: Bearer <jws>`. The HTTP body is the raw JSONL batch, untouched.
- **Detached payload**: the JWS signs a small *claims object*, not the batch body. Body integrity binds via a `body_sha256` claim. Detached-claims is chosen over RFC 7797 detached-over-body so the hub can stream-parse a multi-MB body while validating the JWS upfront, and so batch metadata has a structured signed home.

#### JOSE header

| Field | Value | Why |
|---|---|---|
| `alg` | `EdDSA` | Per ADR-0001; sole supported algorithm |
| `kid` | node's DID URL | Hub resolves via ADR-0007 — no pre-shared key file |
| `typ` | `agnt-rcpt-batch+jws` | Reject a misdirected receipt-JWS at the ingest endpoint |

#### Signed claims

| Claim | Purpose |
|---|---|
| `iat` / `exp` | Replay window. Default `exp = iat + 5min`, aligned to shipper cadence and clock-skew tolerance (see below) |
| `body_sha256` | `sha256:<hex>` of raw JSONL body. Binds JWS to specific bytes |
| `batch_id` | UUID v4 per batch. Log-tracing aid only — not load-bearing for correctness (see *Replay protection* below) |
| `batch_count` | Sanity check vs. parsed body |

#### Hub-side verification order

1. Parse JWS header; extract `kid`.
2. Resolve `kid` via DID resolution (ADR-0007); reject if not in the trust list.
3. Verify JWS signature (EdDSA) over header + claims. On signature failure, force-refresh the DID cache for this `kid` and retry once before rejecting — catches the "key just rotated, cache is stale" case.
4. Check `iat`/`exp` against the hub clock with tolerance (see *Clock skew tolerance* below).
5. Stream body; compute SHA-256; compare to `body_sha256` claim.
6. Per-receipt: re-verify signature and chain link under the same node DID. Persistence is idempotent on `(issuer_did, seq)` — a duplicate receipt with matching chain link is a successful no-op; a duplicate `seq` with a mismatched `prev_hash` is a hard error.

There is **no separate dedup table.** The chain-link check at step 6 *is* the dedup. A retried batch following hub crash is idempotent at the per-receipt layer; CPU on retries is the only cost.

#### Replay protection

`iat`/`exp` constrain the window. An attacker who captures a batch on the wire can only replay within that window. Replay inside the window is harmless: the receipts it contains either land at the hub (idempotent via §4 step 6, no duplication) or were already there (same result). `body_sha256` prevents body substitution under a reused JWS. `batch_id` is for log correlation, not for security — chain-link idempotency is what makes the protocol replay-safe.

#### Clock skew tolerance

`iat`/`exp` are checked against the hub clock with a tolerance of **±5 minutes** by default. Aligned with the `exp = iat + 5min` claim default so a batch produced under acceptable skew round-trips successfully. Operators with tighter clock control (NTP-synchronised fleet) can shorten this; operators with looser control (container fleets, edge nodes) can lengthen, with the proportional cost of a wider replay window.

Shipper-retry semantics: on retry, the shipper **re-signs the JWS with a fresh `iat`** rather than replaying the original. The batch contents are unchanged; only the wrapper is refreshed. This means the JWS-as-durable-artifact property holds for the batch *that is finally accepted by the hub*, not for the JWS bytes that crossed the wire on each retry attempt. Operators expecting bit-identical forensic JWS records across retries should be aware of this.

#### Trust list management

The hub holds a list of authorised node DIDs in an operator-managed file. Properties:

- **Path** is operator config (default: `/etc/agent-receipts/trust.json`).
- **Format** is a JSON document listing each authorised DID with metadata (`did`, `added_at`, optional `notes`).
- **Signed** by the hub's own daemon key (the same DID that signs anchored checkpoints). Trust-list tampering becomes a key-compromise problem, not a filesystem-ACL problem.
- **Reloaded automatically** when the file's mtime changes — no daemon restart required to add or remove a DID.
- **Validation on load**: a malformed or unsigned trust list does not silently become "empty" (which would refuse all ingest). It refuses to load and the hub continues with the last good trust list, logging loudly.

Onboarding a new node: append to the trust list, re-sign, save. Hub picks it up on next mtime tick.

Retirement workflows are distinguished by intent because audit semantics differ:

- **Decommission** — `retired_at: <timestamp>` added to the entry. Hub stops accepting new batches under this DID; historical batches remain readable through the verify CLI.
- **Compromise** — `compromised_at: <timestamp>` added. Hub refuses new ingest. Historical batches *up to* `compromised_at` are readable normally; any persisted receipts after `compromised_at` are retained but flagged as untrusted in verify output.

Both markers are signed as part of the trust-list document. Auditors see in the trust list itself whether a DID is current, retired, or revoked.

#### DID resolution caching

`did:web` resolution involves an HTTPS GET per resolve. Without caching, every batch is a remote dependency. Policy:

- **`did:key`**: no cache. Key is derived from the DID itself; resolution is local and free.
- **`did:web`**: cache with a default TTL of **5 minutes** and **stale-while-revalidate**. Background refresh on access; serves stale during refresh if the DID host is briefly slow.
- **Cache miss + DID host unreachable**: reject the batch with 503; the shipper retries (node has local persistence; no integrity loss).
- **Stale refresh failure**: keep serving the stale entry for a bounded grace window (default 1 hour) while logging loudly. Beyond grace, evict and treat as cache miss on next access.
- **Signature verification failure**: force-refresh the cache for this `kid` and retry verification once before rejecting (see §4 verification order step 3). Catches "key just rotated, our cache is stale" cleanly.

The tradeoff: aggressive caching means a compromised-then-rotated key keeps working at the hub for up-to-TTL. The 5min TTL aligned with the JWS `exp` window is the sweet spot between availability and rotation-latency exposure.

#### Key rotation interaction

`kid` is the node's DID URL — stable across rotations per ADR-0007. The DID resolver returns the public key valid at the JWS `iat` timestamp; mid-flight rotations resolve naturally if the resolver retains key history, with the on-chain ADR-0015 rotation-event witness as a fallback. The hub never holds per-node key material out of band.

#### What the JWS does *not* cover

- **Confidentiality.** JWS is signing, not encryption. TLS handles wire confidentiality. Disclosure payloads (when ADR-0012 envelope is enabled) are already encrypted at the receipt layer; the hub never sees plaintext.
- **Transport-path attestation.** JWS authenticates the node, not the network hop. See "RFC 9421 as an operator-side option" below for HTTP-hop attestation.
- **Per-receipt re-signing.** Receipts are already individually signed (ADR-0001). The JWS is a *batch wrapper*; the hub re-verifies each receipt under the node DID before persisting.

#### JWS vs RFC 9421, and why we land on a hybrid

JWS and [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) solve overlapping but distinct problems. JWS produces a self-contained signed artifact independent of the HTTP transport; RFC 9421 binds the signature to specific HTTP request components (method, target URI, selected headers, body via `Content-Digest` per [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)). The asymmetry that decides the design:

- **JWS artifact survives transport.** A compact JWS is persistable in the hub's database and replayable for forensic verification years later, regardless of what reverse proxies or gateways did to the original request. An RFC 9421 signature is bound to the HTTP request that carried it; replay requires reconstructing the exact original method/target/header set, and any intermediary that mutated `Host`, `X-Forwarded-*`, `Date`, etc. either invalidates verification or forces those headers out of the covered set.
- **Library maturity.** JOSE is a decade old with multiple mature libraries per language. RFC 9421 (Feb 2024) is younger, with uneven coverage across Go/TS/Py. Three SDKs implementing RFC 9421 independently is real interop risk; three SDKs reusing JOSE is not.
- **Composition with ADR-0003.** Receipts already live in the JOSE/JWS world via the W3C VC envelope. JWS keeps us in one signing framework end-to-end.
- **Transport-portability.** If we ever add a non-HTTP ingest path (Kafka, NATS, S3 file-drop, P2P agent-to-agent), the JWS travels unchanged. An RFC 9421 signature does not.
- **What RFC 9421 is genuinely better at**: HTTP-hop attestation — proving the exact HTTP request reached the hub unmodified, with gateway re-signing patterns to compose across intermediaries. That property matters in deployments behind corporate API gateways but is *additional* to integrity, not a substitute for it.

**Decision: JWS is the SDK-level signature; RFC 9421 is an operator-side option, not in SDK scope.** Every node SDK produces a JWS-signed batch; every hub verifies one. Operators with stricter HTTP-hop posture stack RFC 9421 between their gateway and the hub via an Nginx/Envoy module or sidecar — this is a deployment concern, handled outside the daemon binary. The hybrid keeps the SDK surface minimal and library-mature while leaving the door open for HTTP-hop attestation wherever an operator wants it. RFC 9421 is *additional* to the JWS, not a replacement, so adopting it later at a specific deployment does not break interop with SDKs that only know JWS.

### 5. Per-node chains preserved at the hub — no merged chain

The hub verifies each receipt's chain links and stores it under the node's DID. There is one logical chain per node DID, mirroring exactly what each node holds locally. No hub-side `seq` allocator. No Merkle root across nodes. No cross-node ordering.

This is a deliberate **non-decision** so it is not relitigated: global ordering across nodes is *not* in scope for v1, and any future "global chain" proposal — Merkle accumulator across node tips, a hub-issued meta-receipt that commits to a set of node-chain tips, anything that would let an auditor ask "what happened across the fleet between T1 and T2 in causal order" — is a future ADR's problem. The reason: a merged chain requires the hub to be in the signing path or in the ordering path, which dissolves the invariant in §1.

Per-node chains aggregate without ordering. That is enough for v1.

### 6. Hub is `agent-receipts daemon --ingest`, not a separate binary

The hub runs the existing daemon with `--ingest` mode set. Same binary, same schema, same verifier, same `KeySource` (per ADR-0015), same storage. The hub dogfoods the architecture it serves.

Differences in `--ingest` mode versus default:

- **Listens on HTTPS** for `POST /v1/receipts` in addition to (or instead of) the local UDS in default mode. Operators choosing "hub-only" disable the UDS listener; operators running a node-that-is-also-the-hub keep both.
- **Verifies inbound batches** (JWS over batch claims, body digest, chain link verification per receipt, DID authorisation) before persisting. The default daemon's input is trusted local IPC (per ADR-0010); ingest input is untrusted network.
- **Enforces disclosure-envelope precondition.** Hub MUST reject any inbound receipt whose `parameters_disclosure` field is populated in a non-envelope shape (e.g. legacy plaintext or the interim redacted-plaintext from ADR-0012 Phase A partial). Reject with 422 and a diagnostic naming the offending receipt's `seq`. This is belt-and-braces against the *Preconditions* gate being violated by a misconfigured node; it ensures the hub never persists pre-#280 disclosure shapes even if a stale emitter sends them.
- **Owns the anchor schedule** (see §7). Default daemons do not anchor; only the hub does.
- **Holds a configured trust list** of authorised node DIDs (see §4 *Trust list management*). Default daemons do not — they only know their own key.

Same storage layout (SQLite per ADR-0004, one logical chain per node DID), same canonicalisation, same signature scheme. A future operator who wants to verify a hub-stored chain uses the same `agent-receipts verify` CLI against the hub's database that they would use against a node's database.

**Hub DID and key lifecycle.** The hub registers itself the same way a node does — `did:web` for production deployments, `did:key` for development per ADR-0007 — and rotates its signing key via the ADR-0015 rotation-event chain. The hub's DID is what signs anchored checkpoints (§7) and signs the trust-list document (§4); it appears in its own trust store as the recognised checkpoint and trust-list signer, distinct from the node DIDs it authorises for ingest. From the key-management perspective the hub is a node that happens to also accept inbound batches; there is no second key-lifecycle story to maintain.

### 7. External anchoring: S3 with object lock for per-node chain heads

The hub periodically writes per-node chain heads to an S3 bucket with object lock enabled. Each anchor write is a `checkpoint` event as defined by ADR-0015: `(issuer.id, seq, tip_hash, public_key_fingerprint)`, RFC 8785-canonicalised, signed by the hub's own daemon key, written via the ADR-0015 `Write(event_type, payload bytes) → error` contract. `issuer.id` here is the node's DID URL — the same identifier used as `kid` in §4 — so anchor enumeration and per-node-chain lookup share one index.

S3 object lock provides the two properties ADR-0015 demands of a sink:

- **Append-only retention.** Object lock in compliance mode makes objects immutable for the configured retention period; a compromised hub cannot rewrite or delete previously-written checkpoints.
- **Sink-controlled ordering and timestamps.** S3 stamps `LastModified` server-side and assigns version IDs in receipt order. The hub picks the object key, but object lock prevents overwriting any previously-written key — so even though the key is hub-chosen, the *contents* at that key are sink-controlled once written.

The S3 bucket — not the hub — is the trust root for the anchoring claim. Hub compromise is bounded: the attacker controls future receipts and future anchors but cannot rewrite previously-anchored checkpoints, so a verifier with S3 read access can detect any divergence between the hub's current view of a chain and the most recent anchored tip. State explicitly: the integrity property survives total hub compromise as long as the S3 bucket's object-lock configuration was set before the compromise and the attacker did not also compromise the AWS account holding the bucket.

**S3 key naming.** `<bucket>/anchors/<url-encoded-issuer.id>/<seq:020d>.jcs.json`. Zero-padded `seq` ensures lexicographic ordering matches numeric. `.jcs.json` makes the canonicalisation form (RFC 8785 / JCS) explicit at the URL layer so a verifier walking the bucket knows what to expect. Object-lock retention defaults to 1 year; operators with longer compliance horizons configure accordingly.

**Anchor frequency.** Per node, the more recent of (a) every 5 minutes of wall clock during which receipts were ingested, or (b) every 1000 receipts ingested. Quiet nodes do not emit empty anchors; busy nodes do not let the detection window grow unbounded. Both knobs are tunable. The 5min/1000 default is the midpoint between per-batch anchoring (strongest guarantee, highest S3 write cost, anchor latency on the critical path) and hourly anchoring (cheapest, leaves a 60-minute invisible window between truncation and detection). Operators with stricter audit posture shorten the cadence; operators with cost-sensitive sinks lengthen it.

Cost grounding (so the knob is concrete): S3 PUT with object lock is approximately $5 per million requests. A 1000-node deployment anchoring every 5 minutes is ~12 anchors/hour × 1000 nodes × 24h × 30d ≈ 8.6M PUTs/month ≈ $43/month. The cadence default is not cost-bound at any plausible fleet size.

**Hub-side failure mode.** Hub-emitted checkpoints use ADR-0015's `queue` mode by default — staged in a local outbox if the sink is unreachable, flushed when it returns. Operators with stricter compliance posture configure `block` (hub stops ingesting if anchoring is unavailable); `drop` is also available per ADR-0015's menu for checkpoint events but means the truncation-detection window grows without bound during sink outages. Defaults align with ADR-0015 §"Checkpoint events".

**Cold start.** A fresh hub joining a node mid-history records its join point. The hub's first anchored checkpoint for a node carries `joined_at_seq: <first_seq_observed>`. Verifiers reading the anchor stream know: anchored-tail-integrity applies from `joined_at_seq` onward; for receipts before that point only the node's local chain provides integrity. This composes with §1's invariant — we do not pretend the hub knows about pre-join history; we record the seam and let verifiers reason about it.

### 8. Scope: single-tenant for v1

One operator. One curated list of authorised node DIDs. One S3 bucket. The hub is sized for a small fleet under one administrative boundary — the laptop-plus-EC2 shape that motivates this ADR.

Multi-tenant deployment — per-tenant DID scoping, per-tenant S3 buckets, quotas, isolation between tenants, a UI to manage trust lists — is **deferred to a later ADR**. The deferral is mostly about operator surface, but not purely: multi-tenant introduces real blast-radius concerns (compromise of one tenant's hub-resident chain must not pollute another's; ciphertext-disclosure aggregation per-tenant must not leak across tenants), and those are non-trivial design questions. The v1 single-tenant assumption is not load-bearing for the integrity model in §1–§7, but the door is explicitly *not* "purely an operator-surface change" when it comes to multi-tenant — that's a real follow-up ADR worth.

### 9. Operational backpressure and outbox

Hub capacity is finite. When ingest outpaces verify-and-persist, the hub responds with HTTP **429** including a `Retry-After` header. The node-side shipper backs off and accumulates batches in a bounded local outbox (default ~10,000 receipts; operator-tunable). When the outbox fills during a prolonged hub outage:

- Shipper applies **`EAGAIN`-style backpressure to local emitters**, reusing the ADR-0010 mechanism.
- Emitter increments its drop counter and flushes the counter alongside its next successful event.
- Daemon records the gap as a synthesised **`events_dropped`** receipt in the local chain — the standard ADR-0010 visibility pattern.

This composes the existing in-chain-visibility pattern from ADR-0010 through the hub layer rather than inventing a new one: the hub's "I'm full" signal travels back to the emitter and ends up *in the chain*, so the auditor sees the gap as a synthesised receipt rather than as silent absence. The §1 invariant holds throughout — the local chain remains authoritative, and what's in it stays in it.

## Architecture

```
emitters (openclaw / hermes / mcp-proxy)
   ↓ UDS SOCK_STREAM (JSONL, per ADR-0010)
local agent-receipts daemon
   ├─ canonicalize / sign / hash-chain
   ├─ persist to local SQLite (source of truth)
   └─ shipper goroutine + bounded outbox
         ↓ HTTPS POST /v1/receipts
         ↓   body: JSONL batch
         ↓   header: Authorization: Bearer <JWS over claims incl. body_sha256>
hub agent-receipts daemon (--ingest mode)
   ├─ verify JWS (kid → DID resolution → trust list)
   ├─ verify body_sha256 matches body
   ├─ re-verify each receipt's signature + chain link
   ├─ reject pre-envelope plaintext disclosure (precondition check)
   └─ persist per-node chains to SQLite
         ↓ periodic anchor job (5min / 1000 receipts, whichever first)
   S3 bucket with object lock
     <bucket>/anchors/<issuer.id>/<seq:020d>.jcs.json
     (per-node chain heads, signed by hub's daemon key)
```

## Security considerations

### Trust-list integrity is load-bearing

The hub's authorisation decision is "is this `kid` in the trust list?" — so the trust list is structurally as important as the signing key. Mitigations:

- Trust list is **signed** by the hub's own daemon key. An attacker with filesystem-write access to the trust list cannot add a DID; they would need the hub's signing key.
- Trust list reload **validates the signature** before swapping in. A failed signature check keeps the previous good list in effect and logs loudly.
- Trust-list **changes are themselves anchored**: appending a `trust_list_updated` event to the hub's local chain (signed by the hub key) and anchoring it to S3 alongside checkpoints makes the trust-list history something the hub cannot rewrite alone, even with key compromise post-anchor.

### DID resolution is an external dependency

A compromise of a node's `did:web` document (HTTPS-hosted DID document) allows an attacker to substitute a different public key. The hub will accept JWS-signed batches under the attacker's key once cache TTL expires and refreshes. Mitigations:

- Operator should pin DID-host TLS certificates where feasible.
- The signature-failure-triggered cache invalidation (§4 verification order step 3) gives a small additional window of "use stale cache when the new key looks compromised", at the cost of an extra resolution attempt per attacker-signed batch.
- Receipts are individually signed *under the same key being substituted*, so this attack is not unique to the hub — it is a general ADR-0007 / DID-method threat. The hub does not amplify it but does inherit it.

### Hub compromise blast radius (with envelope disclosure)

Once ADR-0012 envelope ships and the *Preconditions* gate clears, the hub holds **ciphertext** disclosures, not plaintext. Hub compromise exposes:

- The encrypted disclosure corpus across all nodes (one place, all secrets, but ciphertext).
- The hub's signing key and trust list (lets the attacker forge future checkpoints and onboard rogue node DIDs going forward — but not retroactively, since prior anchors are immutable).
- The hub's local SQLite (lets the attacker observe metadata: which nodes are active, what `seq` they're at, when receipts were emitted).

What is **not** exposed by hub compromise alone:

- Disclosure plaintext — that requires the forensic private key, which is escrowed off-hub per ADR-0012.
- Past anchored checkpoints — S3 object lock makes them immutable for the retention period.
- Per-receipt signatures — those are still valid under each node's DID; a verifier with the chain can still verify against the issuer's DID without trusting the hub.

The hub's compromise is therefore bounded by *what the forensic responder controls* and *what the anchor sink has already retained*. The integrity claim survives total hub compromise; the confidentiality claim survives unless the forensic key is also compromised.

### AWS account compromise

If the AWS account holding the anchor bucket is compromised, object lock is no longer load-bearing — the attacker can change retention, delete objects, replace the bucket. The integrity claim degrades to "as good as the AWS account's security boundary". Operators with the strictest posture should:

- Host the anchor bucket in a separate AWS account from the hub's compute.
- Use SCPs to prohibit object-lock modification and bucket deletion at the org level.
- Consider multi-region replication of anchors to a second account for additional defence-in-depth.

This ADR does not mandate these; they are operator choices proportional to threat posture.

### Clock skew abuse

A node with a deliberately-skewed clock can extend its replay window (loose tolerance) or make legitimate batches fail (tight tolerance). The default ±5 minutes is permissive enough for typical NTP drift and tight enough that practical replay windows stay short. Operators noticing chronic skew from one node should investigate the node's NTP configuration rather than loosening the global default.

## Consequences

### Positive

- Multi-node deployments get aggregation without surrendering per-node integrity. An auditor queries one hub instead of N hosts; verification still runs against per-node DIDs.
- ADR-0015's anchoring commitment gets a concrete reference implementation. The "load-bearing external sink" stops being aspirational.
- The hub adds no new trust root for receipts; for anchoring, the S3 bucket is the trust root (not the hub). Existing chain-verification tooling works against the hub's database with no protocol change.
- Reusing the daemon's signing key for transport auth, trust-list signing, and checkpoint signing means there is one credential to rotate, one DID to manage, one set of key-rotation semantics (ADR-0015 carries through).
- Backpressure composes the ADR-0010 `events_dropped` pattern through the hub layer — gaps remain visible *in chain* rather than silent.

### Negative / explicitly accepted

- **New failure mode: shipper crash or hub outage.** Local persistence absorbs the shipper crash (the receipt is still in SQLite; the shipper retries on restart). Hub outage is handled by exponential backoff retry in the shipper, bounded outbox, and EAGAIN backpressure to emitters when the outbox fills. Integrity is unaffected in either case — the local chain still verifies; the hub catches up when reachable.
- **Hub operator inherits a key-management responsibility.** The hub signs its own checkpoints and its trust list, so it has a `KeySource` of its own. Slots into ADR-0015's BYOK abstraction unchanged — a hub operator can put the hub's key in KMS the same way a node operator can.
- **TLS in transit is table stakes; end-to-end encryption is the ADR-0012 envelope.** Receipts are signed at the node and (when disclosure is enabled) carry ciphertext per ADR-0012. Hub compromise exposes ciphertext, not plaintext; full plaintext exposure additionally requires forensic-key compromise. The pre-envelope assumption ("redaction policy permits raw payloads") is now structurally rejected by the §6 precondition check — the hub will not accept pre-envelope disclosure shapes.
- **Transport-layer auth (mTLS, Tailscale, WireGuard) is defence-in-depth, not the integrity guarantee.** Out of scope for v1. Mentioned for operators with stricter network posture: nothing in this ADR prevents running the HTTPS endpoint behind a WireGuard mesh or mTLS gateway. The JWS auth still applies on top.
- **Terminology rename (NDJSON → JSONL) is a project-wide sweep.** Documentation, code comments, CLI help text, and any config field names referring to NDJSON change to JSONL. Track as a separate cleanup issue; no behaviour change.
- **Hub adds an installable component.** ADR-0010 already obliged operators to install a service-managed daemon; the hub is an additional deployment of the same binary. Packaging burden is incremental, not new.

## Alternatives considered

- **UDP transport.** A datagram per receipt or per batch. Rejected: UDP loss is permanent divergence between the local chain (which has the receipt) and the hub (which does not), and the throughput case that would justify UDP does not exist at human-scale agent traffic. Loss cost is permanent; benefit is zero.

- **gRPC streaming as the default.** Bidirectional streaming, schema-typed payloads, built-in flow control. Rejected as a default: gRPC is harder to expose through corporate firewalls and reverse proxies, harder to debug with off-the-shelf tools, and brings a schema-compiler dependency to every SDK for no integrity benefit at this scale. Reasonable as a future addition for a high-throughput deployment; not the default.

- **mTLS-only auth (no JWS at the application layer).** Rejected: TLS certs are not the daemon's signing key, introduce a parallel PKI for transport auth, and the integrity artifact dies with the TLS connection. JWS reuses the existing Ed25519 daemon key and survives transport. mTLS remains available as a *defence-in-depth* layer on top of JWS for operators with stricter network posture.

- **Pull model (hub polls each node's read endpoint).** Hub initiates connection to nodes, fetches batches. Rejected: inverts the firewall-friendliness story — every node must now expose an inbound HTTPS endpoint reachable from the hub, which is exactly what most node deployments (laptops, restricted EC2) cannot provide. Push model has nodes initiate outbound HTTPS, which any node can do.

- **Merged global chain at the hub.** A hub-side `seq` allocator and a single chain across all nodes. Rejected: requires the hub to be in the signing or ordering path, dissolving the §1 invariant. Per-node chains preserve the integrity guarantee under hub compromise; a merged chain does not.

- **Separate hub binary.** A dedicated `agent-receipts-hub` distinct from the daemon. Rejected: same schema, same verifier, same storage, same canonicalisation, same key-management story — splitting the binary doubles the maintenance surface for no functional reason. Dogfooding the daemon as the hub also means every bug in one is exercised in the other.

- **New API-key credential instead of reusing the daemon key.** Hub-issued bearer tokens or operator-issued API keys. Rejected: introduces a second secret per node, a second rotation story, a second compromise surface. The daemon's Ed25519 key is already the node's strongest authentication primitive; using it for transport auth via JWS reuses what is already there.

- **Hub as trust root (no external anchoring).** Drop the S3 anchor and treat the hub's local store as the authoritative aggregation point. Rejected: a hub compromise then has no external check, and ADR-0015's post-compromise integrity claim has no anchor to land on. The whole point of the sink is to be something the hub does not control.

- **Federated multi-hub / hub-to-hub replication.** Two or more hubs replicating to each other for redundancy or cross-region resilience. Out of scope for v1. The S3 anchor provides the durable cross-region record; hub-to-hub replication is a future ADR if and when a real deployment needs it. Per-node chains already give us a poor-man's "shard by node DID" sharding model that defers the multi-hub question naturally.

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — same key signs receipts, the JWS-wrapped batch, the trust list, and anchored checkpoints.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — wire format for batch payloads, anchor checkpoints, and trust-list signature input.
- [ADR-0003 (W3C VC envelope)](./0003-w3c-vc-envelope-format.md) — places the protocol in the JOSE/JWS world; informs §4's JWS choice.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — hub uses the same store layout per node DID.
- [ADR-0007 (DID method strategy)](./0007-did-method-strategy.md) — `did:web` for hub-registered production nodes, `did:key` for laptops; same resolution path on the hub's authorisation side. Phase A is a precondition for this ADR.
- [ADR-0009 (canonicalisation and schema consistency)](./0009-canonicalization-and-schema-consistency.md) — null-handling rules apply identically to anchor payloads and trust-list documents.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — the substrate; the hub is the same daemon in `--ingest` mode. The `events_dropped` pattern from ADR-0010 composes through the hub layer for backpressure (§9).
- [ADR-0012 (payload disclosure policy)](./0012-payload-disclosure-policy.md) — Phase A envelope is a precondition for this ADR; the hub's §6 precondition check enforces that pre-envelope disclosure shapes never reach the hub.
- [ADR-0015 (key rotation, BYOK, external anchoring)](./0015-key-rotation-byok-anchoring.md) — supplies the `KeySource` interface and anchor write contract; this ADR pins the contract to S3 with object lock and is structurally ADR-0015 Phase B. Phase A is a precondition for this ADR.
