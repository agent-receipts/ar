# ADR-0015: Key Rotation, BYOK Abstraction, and External Anchoring

## Status

Proposed

## Context

The daemon (ADR-0010) holds a single Ed25519 signing key. Three gaps remain in the design:

1. **Rotating that key** without breaking historical chain verification.
2. **Where the key lives.** The daemon assumes a file on disk with `0600` permissions. That works for solo-dev but is not the answer enterprise operators will accept (HSM, cloud KMS, customer-managed key store).
3. **What happens when the daemon itself is compromised.** Chain verification catches mid-chain tampering but not tail truncation ([#171](https://github.com/agent-receipts/ar/issues/171)) or a forged rotation history. Without external anchoring of rotation events and periodic chain commitments, "the daemon protects the chain" is a circular argument — the same key that signs the receipts also signs the rotation history.

The threat model ([#155](https://github.com/agent-receipts/ar/issues/155)) names tail-truncation and post-compromise integrity as load-bearing concerns. Both depend on a sink the daemon does not control. Centralized credential-vault tools cannot match this property by their architecture — they hold customer credentials and SaaS access in the call path, so a compromise cascades. The daemon holds *one* signing key, no customer credentials, and (with anchoring) a verifiable history that survives daemon-key compromise.

This ADR scopes the design that closes those three gaps. Implementation is split into follow-on issues; this document is the Proposed-status ADR only.

## Decision

Two primitives, designed together because their interfaces interlock: a `KeySource` abstraction for where the signing key lives, and an external-anchor write contract for what survives daemon compromise.

### `KeySource` interface

The daemon reads its signing key from a configurable backend rather than a fixed filesystem path. Operations the interface MUST support:

- **`Sign(canonical bytes) → (signature bytes, algorithm tag, error)`** — the primitive. Some adapters (file-based) hold the private key in process memory; others (PKCS#11, cloud KMS) keep it remote and submit canonical bytes for signing without ever exposing the key to the daemon process. The algorithm tag accompanies the signature so receipts and rotation events carry an unambiguous verification recipe.
- **`PublicKey() → (key material, algorithm tag, error)`** — for verifier consumption and for emitting fingerprints into rotation events.
- **`Rotate() → (old fingerprint, new fingerprint, old algorithm, new algorithm, transcript bytes, error)`** — produces a new signing key and returns the fingerprints (computed per the canonical-bytes rule below) plus the canonical bytes of the rotation event itself. The *outgoing* key signs the transcript before the new key takes over. Both algorithm tags are returned so the caller can populate the rotation event's `old_algorithm` and `new_algorithm` schema fields directly; same-algorithm rotations return the same value twice, cross-algorithm rotations (e.g. Ed25519 → ML-DSA) return distinct outgoing and incoming tags.
- **`Init(config) → error`** and **`Teardown() → error`** — adapter-specific bring-up and shutdown. Init MUST fail loudly at daemon start if the backend is unreachable; the daemon refuses to come up rather than silently fall through to a degraded mode.

Backends in scope (adapters land in follow-on issues, not this ADR):

- **File** (default) — current behaviour, `~/.agent-receipts/signing.pem` with `0600` (and `signing.pem.pub` `0644`), matching the existing mcp-proxy `init` convention. Solo-dev tier.
- **PKCS#11** — HSM, smartcard, or TPM via the standard interface.
- **Cloud KMS** — AWS KMS, GCP KMS, Azure Key Vault. Key never leaves the KMS; daemon submits canonical bytes for signing each receipt.

The interface is **algorithm-agnostic by design**. ADR-0001 (Ed25519) is the current commitment, but [#32](https://github.com/agent-receipts/ar/issues/32) (algorithm agility) requires that adding a post-quantum signing scheme later does not force a `KeySource` redesign. Operation signatures MUST NOT bake Ed25519-specific assumptions — `Sign` operates on canonical bytes and returns opaque signature bytes plus an algorithm tag.

**Error semantics.** Adapters surface backend-specific errors (KMS rate limits, HSM lock-out, network partitions) as structured `KeySource` errors with a `transient` flag. The daemon retries transient errors with bounded backoff and treats persistent errors as a halt condition — the daemon refuses to sign new receipts rather than emit unsigned ones.

### Rotation event schema

When the daemon rotates its signing key, a `key_rotated` synthetic receipt is appended to the local chain. Required fields (in addition to the daemon-supplied chain fields `seq`, `prev_hash`, `ts_recv` per [ADR-0010](./0010-daemon-process-separation.md)'s schema-split — these are the daemon-internal names; the verifier-facing AgentReceipt envelope wraps them as `credentialSubject.chain.sequence`, `previous_receipt_hash`, and the receipt's `issuanceDate` at emission):

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Constant `"key_rotated"` |
| `old_key_fingerprint` | string | SHA-256 of the outgoing public key (raw bytes, see "Fingerprint canonical form" below), multibase-encoded `u`-prefixed base64url (per ADR-0001 encoding choice) |
| `new_key_fingerprint` | string | Same encoding, of the incoming public key |
| `old_algorithm` | string | Algorithm tag of the outgoing key (e.g. `"ed25519"`). Used to verify the rotation event's own signature, since `signed_with: "old"`. |
| `new_algorithm` | string | Algorithm tag of the incoming key (e.g. `"ed25519"`). Used to verify subsequent receipts. In same-algorithm rotations equal to `old_algorithm`; differs only across cross-algorithm migrations (e.g. Ed25519 → ML-DSA per [#32](https://github.com/agent-receipts/ar/issues/32)). |
| `signed_with` | string | Constant `"old"` — the rotation event itself is signed with the *outgoing* key, anchoring the transition to the key being retired |

**Fingerprint canonical form.** Fingerprints are SHA-256 over the *raw public key bytes* as defined per algorithm (Ed25519: the 32-byte public key per [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) §5.1.5; future algorithms specify their canonical raw encoding when added). SPKI/PEM wrappers and backend-specific handles (KMS key IDs, PKCS#11 object handles) MUST NOT be hashed — those representations vary across adapters and would produce different fingerprints for the same underlying key.

The next receipt after a `key_rotated` event is signed with the new key. Verifiers chain through rotations by:

1. Resolving `old_key_fingerprint` via the configured key registry (DID per ADR-0007, file, or KMS reference) to obtain the outgoing public key, then verifying the `key_rotated` event's signature with that public key under `old_algorithm`.
2. Resolving `new_key_fingerprint` via the same registry to obtain the incoming public key.
3. Treating subsequent receipts as signed by the incoming public key under `new_algorithm`, until the next `key_rotated` event.

Rotation events SHOULD carry a `proof.verificationMethod` (DID URL or equivalent) that resolves to the outgoing public key, mirroring the receipt envelope. The `old_key_fingerprint` / `new_key_fingerprint` fields exist for fast chain-traversal indexing and for offline verification when DID resolution is unavailable; they are not a substitute for a resolvable verification method when one can be provided.

Signing the rotation event with the outgoing key is the standard cryptographic-rotation idiom but it is also the failure mode if the outgoing key was already compromised at the moment of rotation: a compromised daemon could forge a rotation event that "retires" the legitimate key in favour of an attacker-controlled key. This is why **rotation events MUST be mirrored to the external anchor** (next section) — the anchor is the only construct that prevents an attacker from rewriting the rotation history alongside the receipt history.

### External anchor write contract

The daemon writes a subset of events to an operator-configured external sink. Two event types:

- **`rotation`** — every `key_rotated` receipt is mirrored to the sink immediately after it is appended to the local chain.
- **`checkpoint`** — at operator-configured intervals (default: hourly), the current `(issuer.id, seq, tip_hash, public_key_fingerprint)` tuple is written to the sink. `issuer.id` identifies the daemon emitting the checkpoint, so checkpoints from multiple daemons (multi-host or test environments) cannot be conflated. `tip_hash` is the SHA-256 of the canonical bytes of the most recently appended receipt itself — not its `prev_hash` — encoded as `sha256:<hex>` to match the repo's existing chain-hash format (`previous_receipt_hash`, `hashReceipt` helpers, `spec/AGENTS.md`). This means an anchored `tip_hash` can be passed straight to existing `ExpectedFinalHash`-style verifier APIs without re-encoding. The checkpoint commits *to* the tip; a verifier comparing the local chain against the most recent anchored checkpoint detects tail truncation as a mismatch on `issuer.id`-scoped `seq` or `tip_hash`.

Transport-agnostic. The sink interface is a single operation:

```
Write(event_type, payload bytes) → error
```

`payload bytes` MUST be the same RFC 8785 canonical-JSON serialization the receipt itself uses (per ADR-0002, ADR-0005, and ADR-0009), so any SDK or sink adapter produces byte-identical anchor payloads for the same logical event. This is the same canonicalization rule that makes cross-SDK signature verification work; relaxing it for anchors would dissolve verifier interop with the sink.

**A sink is not just any endpoint.** To qualify as an anchor (rather than mere transport), the sink MUST provide:

- **Append-only retention** — a compromised daemon writing later events cannot rewrite or delete earlier entries. Object-lock on S3, write-only logs, transparency-log Merkle trees, and managed SIEM ingestion all qualify; a plain webhook to an attacker-mutable endpoint does not.
- **Sink-controlled ordering or timestamps** — the daemon does not get to choose the entry's position or recorded time; the sink does. This is what makes "the daemon does not control the anchor" structurally true.

Adapters land in follow-on issues; representative targets that meet both properties: S3 PUT with object-lock, transparency log append, customer SIEM ingestion endpoint with sequence-stamping, syslog over TLS to an immutable log host. A bare webhook POST without these properties is a transport, not an anchor — operators who want the post-compromise integrity claim must choose a sink that delivers them.

**Failure semantics on sink unavailability — operator-configurable, not architectural.** Three modes:

| Mode | Behaviour | When to choose |
|---|---|---|
| `block` | Daemon stops accepting new events when the sink is unavailable. Per ADR-0010, emitters are non-blocking and drop events via the `EAGAIN` mechanism while the daemon refuses; those drops are recorded as `events_dropped` synthetic receipts in the local chain. | Maximum integrity in the sense of *no silent loss* — gaps appear in the chain rather than absent. Lowest availability. Compliance-driven deployments where any discoverability gap MUST be in-chain rather than untracked. |
| `queue` (default) | Daemon writes the event to the chain and a local outbox; outbox flushes when the sink recovers. Operator alerts on outbox depth. | Balanced default. Tolerates transient sink outages — events in the outbox are tracked locally but **not yet anchored** until the sink acknowledges. Operators alert on outbox depth so prolonged queueing is visible. |
| `drop` | Daemon writes the event to the chain only, logs the sink failure, continues. | Available even when the sink is permanently down. Operator explicitly accepts a discoverability gap. |

Same code path, same event format, three behaviours selected by config.

### Periodic chain commitments — scope decision

**Decision: in-ADR.** The chain-checkpoint mechanism is described above as a peer of rotation events, not as a separate construct.

Rationale: tail truncation ([#171](https://github.com/agent-receipts/ar/issues/171)) and forged-tail-after-compromise both fall to the same primitive — periodic commitments to a sink the daemon does not control. Splitting into a sibling ADR would force operators to configure two sinks for one threat surface and would fragment the documented mitigation across two specs.

Implementation phasing keeps the integrity claim honest:

- **Phase A** (the ADR's first implementation): rotation events anchored. Tail integrity is named as a known gap until Phase B.
- **Phase B** (follow-on issue): checkpoint anchoring lands. Tail integrity claim becomes defensible. Threat model ([#155](https://github.com/agent-receipts/ar/issues/155)) updates concurrently to assert the conditional integrity guarantee.

## Consequences

### Positive

- **Post-compromise integrity becomes a defensible claim.** Conditional on a configured external sink: without anchoring, post-compromise integrity remains aspirational; with anchoring, the chain's history survives daemon-key compromise. The conditional is now load-bearing and explicitly stated.
- **Algorithm agility falls out of the abstraction.** ADR-0001's Ed25519 commitment narrows from "baked in" to "current default." Post-quantum migration ([#32](https://github.com/agent-receipts/ar/issues/32)) does not require a `KeySource` redesign.
- **Enterprise key custody is reachable without re-architecting.** HSM, cloud KMS, multi-recipient escrow all absorb into the adapter pattern. The daemon's interface to keys is the same regardless of where they live.
- **Tail truncation gets a structural answer.** [#171](https://github.com/agent-receipts/ar/issues/171) moves from "known gap, no roadmap" to "Phase B implementation."
- **Cross-cuts cleanly with ADR-0012.** ADR-0012's forensic encryption keypair is a separate construct from the signing key; lifecycles are independent. Neither key surface reuses the other, exactly the property ADR-0012 already commits to.

### Negative / explicitly accepted

- **Two-event-type sink surface (rotation + checkpoint).** Mitigated by serving both from the same `Write` interface and the same operator config. Documented as one sink with two event types, not as two systems.
- **Sink-unavailability mode is an operator choice with no universal default.** `queue` is the proposed default but `block` and `drop` deployments will exist. Documented prominently with deployment-tier guidance.
- **`queue` mode has a non-zero post-compromise integrity window.** Events in the outbox between local-write and sink-acknowledge are tamper-evident in the chain but not yet anchored externally. A daemon compromised mid-window can rewrite the outbox; sink-acknowledged events are immune. Operators in tightly compliance-bound deployments should choose `block` instead, accepting the availability tradeoff.
- **Old public keys (or their resolution records) must be retained for verification of historical chain segments.** Retired *private* signing keys SHOULD be destroyed once rotation is anchored externally — unlike ADR-0012's forensic decryption keypair (which legitimately requires private-key retention to read historical encrypted payloads), signing verifiers only need the public key. Reducing private-key blast radius is a positive consequence of rotation, not a tax on it.
- **Rotation event itself is signed with the outgoing key.** Standard cryptographic-rotation idiom, but documented because operators rotating in response to suspected compromise need to understand they are authenticating the transition with the key they are already retiring. The mitigation is anchoring every rotation event to the external sink, so a compromised daemon cannot forge a backdated rotation that the anchor does not know about.
- **The `KeySource` interface cannot encode every backend's idiosyncrasies.** KMS rate limits, HSM lockouts, cloud throttling all surface as backend-specific errors with a structured `transient` flag; the daemon's retry/halt policy is uniform across adapters but the operator's alerting must be backend-aware.
- **Sink configuration is now a load-bearing operational concern, not an optional feature.** Operators who skip configuring an external sink keep the chain integrity guarantees they had before this ADR — but lose the post-compromise integrity guarantee that motivates the design. The `KeySource` work and the anchor work are both required for the full claim.

## Alternatives considered

- **Drop BYOK; keep file-only key storage.** Solo-dev would still work, but the daemon would have nothing to say to operators with HSM or KMS requirements. Rejected: the daemon's value proposition extends to deployments where on-disk keys are non-starters.
- **Anchor every receipt to the external sink, not just rotations and checkpoints.** Strongest possible integrity, but the sink becomes a per-receipt latency component and a per-receipt outage point. Rejected as the wrong default; the sink interface does not preclude operators choosing this mode if their sink can handle the throughput.
- **Bake the sink interface into ADR-0010 (daemon process separation).** Considered when ADR-0010 was drafted but excluded as scope. Splitting external anchoring out lets ADR-0010 ship without the anchor adapter ecosystem and lets this ADR settle the integrity story independently.
- **Use the same `KeySource` adapter for the forensic keypair (ADR-0012).** Tempting because the abstraction shape is similar (Sign vs. Decrypt). Rejected: signing-key lifecycle (rotate freely, retain old keys for verification) and forensic-key lifecycle (do not rotate without re-encrypting historical receipts, retain old private keys forever) are different enough that one interface would force compromises in both.
- **Sibling ADR for periodic chain commitments.** Considered as a cleaner separation of concerns. Rejected: same sink, same operator config surface, same threat lineage. Two ADRs would fragment the mitigation story across two documents readers would need to assemble themselves.

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — current default algorithm; the `KeySource` interface narrows this from "baked in" to "current default."
- [ADR-0007 (DID method strategy)](./0007-did-method-strategy.md) — public-key resolution path. Rotation events reference fingerprints; verifiers resolve those via the DID method chosen there.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — substrate this ADR sits on; the daemon is the only thing that holds a `KeySource`.
- [ADR-0012 (payload disclosure policy)](./0012-payload-disclosure-policy.md) — separate keypair (forensic encryption), separate lifecycle. Informs the "do not reuse keys across purposes" property recorded here.
