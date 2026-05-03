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

- **`Sign(canonical bytes) → signature, error`** — the primitive. Some adapters (file-based) hold the private key in process memory; others (PKCS#11, cloud KMS) keep it remote and submit canonical bytes for signing without ever exposing the key to the daemon process.
- **`PublicKey() → key material, algorithm tag, error`** — for verifier consumption and for emitting fingerprints into rotation events.
- **`Rotate() → new public key material, rotation transcript, error`** — produces a new signing key, returns the public-key fingerprints needed to construct the rotation event below. The transcript is the canonical bytes of the rotation event so the *outgoing* key signs it before the new key takes over.
- **`Init(config) → error`** and **`Teardown() → error`** — adapter-specific bring-up and shutdown. Init MUST fail loudly at daemon start if the backend is unreachable; the daemon refuses to come up rather than silently fall through to a degraded mode.

Backends in scope (adapters land in follow-on issues, not this ADR):

- **File** (default) — current behaviour, `~/.agent-receipts/signing.key` with `0600`. Solo-dev tier.
- **PKCS#11** — HSM, smartcard, or TPM via the standard interface.
- **Cloud KMS** — AWS KMS, GCP KMS, Azure Key Vault. Key never leaves the KMS; daemon submits canonical bytes for signing each receipt.

The interface is **algorithm-agnostic by design**. ADR-0001 (Ed25519) is the current commitment, but [#32](https://github.com/agent-receipts/ar/issues/32) (algorithm agility) requires that adding a post-quantum signing scheme later does not force a `KeySource` redesign. Operation signatures MUST NOT bake Ed25519-specific assumptions — `Sign` operates on canonical bytes and returns opaque signature bytes plus an algorithm tag.

**Error semantics.** Adapters surface backend-specific errors (KMS rate limits, HSM lock-out, network partitions) as structured `KeySource` errors with a `transient` flag. The daemon retries transient errors with bounded backoff and treats persistent errors as a halt condition — the daemon refuses to sign new receipts rather than emit unsigned ones.

### Rotation event schema

When the daemon rotates its signing key, a `key_rotated` synthetic receipt is appended to the local chain. Required fields (in addition to the standard chain fields `seq`, `prev_hash`, `ts_recv` supplied by the daemon):

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Constant `"key_rotated"` |
| `old_key_fingerprint` | string | SHA-256 of the outgoing public key, multibase-encoded `u`-prefixed base64url (per ADR-0012 encoding choice) |
| `new_key_fingerprint` | string | Same encoding, of the incoming public key |
| `algorithm` | string | Tag from the `KeySource` `PublicKey()` call (e.g. `"ed25519"`); reserved for future PQ migration per [#32](https://github.com/agent-receipts/ar/issues/32) |
| `signed_with` | string | Constant `"old"` — the rotation event itself is signed with the *outgoing* key, anchoring the transition to the key being retired |

The next receipt after a `key_rotated` event is signed with the new key. Verifiers chain through rotations by:

1. Verifying the `key_rotated` event's signature against `old_key_fingerprint`.
2. Treating subsequent receipts as signed by the key matching `new_key_fingerprint`.
3. Resolving each fingerprint to a public key via the configured key registry (a DID per ADR-0007, a file, or a KMS reference).

Signing the rotation event with the outgoing key is the standard cryptographic-rotation idiom but it is also the failure mode if the outgoing key was already compromised at the moment of rotation: a compromised daemon could forge a rotation event that "retires" the legitimate key in favour of an attacker-controlled key. This is why **rotation events MUST be mirrored to the external anchor** (next section) — the anchor is the only construct that prevents an attacker from rewriting the rotation history alongside the receipt history.

### External anchor write contract

The daemon writes a subset of events to an operator-configured external sink. Two event types:

- **`rotation`** — every `key_rotated` receipt is mirrored to the sink immediately after it is appended to the local chain.
- **`checkpoint`** — at operator-configured intervals (default: hourly), the current `(seq, prev_hash, public_key_fingerprint)` triple is written to the sink.

Transport-agnostic. The sink interface is a single operation:

```
Write(event_type, payload bytes) → error
```

Adapters land in follow-on issues; representative targets: webhook POST, S3 PUT with object-lock, transparency log append, customer SIEM ingestion endpoint, syslog over TLS.

**Failure semantics on sink unavailability — operator-configurable, not architectural.** Three modes:

| Mode | Behaviour | When to choose |
|---|---|---|
| `block` | Daemon refuses to accept new emitter events until the sink succeeds. | Maximum integrity, lowest availability. Compliance-driven deployments where a discoverability gap is unacceptable. |
| `queue` (default) | Daemon writes the event to the chain and a local outbox; outbox flushes when the sink recovers. Operator alerts on outbox depth. | Balanced default. Tolerates transient sink outages without losing integrity guarantees once the sink recovers. |
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
- **Old private keys must be retained for verification of historical chain segments.** Rotation does not free the operator from keeping retired key material reachable to verifiers. (This mirrors ADR-0012's "old forensic private keys retained forever" property.)
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
