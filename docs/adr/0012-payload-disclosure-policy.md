# ADR-0012: Payload Disclosure Policy (`parameterDisclosure`)

## Status

Proposed

## Context

Receipts today commit to action parameters via `parameters_hash` only. That is the right default — it is privacy-preserving, tamper-evident, and small. But the most common forensic question after an incident is "what did the agent actually send?" and a hash cannot answer it.

The OpenClaw plugin already documents an opt-in `parameterPreview` config that selectively discloses parameters by risk class. The TypeScript SDK exposes the field shape as `parameters_preview` on `Action` ([sdk/ts/src/receipt/types.ts](../../sdk/ts/src/receipt/types.ts)), with a CHANGELOG warning that the value is permanent and signed and "must never be auto-populated from raw arguments". Python and Go SDKs do not have the field. The MCP proxy has no equivalent knob, though it does have opt-in AES-256-GCM encryption of redacted audit fields via `BEACON_ENCRYPTION_KEY` ([mcp-proxy/cmd/mcp-proxy/main.go](../../mcp-proxy/cmd/mcp-proxy/main.go)) — prior art for non-signing key handling.

The result is that the forensic question gets a different answer depending on which channel produced the receipt. We want a uniform, operator-controlled, privacy-preserving-by-default position across every emitter, documented as a deliberate design decision rather than buried in installation config.

### Forces in tension

- **Forensic completeness.** Hash-only receipts can prove tampering but cannot answer "what command ran?" without out-of-band logs.
- **Privacy / least-disclosure.** Payloads routinely contain API keys, PII, file contents, and prompt text. Storing plaintext changes the threat model and pulls the receipts store into GDPR / data-handling scope.
- **Tamper-evidence.** Anything visible to forensics must also be tamper-evident, or it is worse than no record at all.

### Architectural facts that further constrain the solution

- **Storage will be pluggable.** SQLite is the only adapter today, but the contract must work for Postgres, S3-backed object stores, append-only files, and OTel exporters. Encryption cannot be a property of any single adapter.
- **SIEM / telemetry fan-out is on the roadmap.** Those sinks must receive enough for trend analysis (counts, rates, action types, risk levels, hashes, timing, decisions) but never raw payloads. The disclosure boundary needs to be expressible as a single key, not as N per-adapter redaction configs.
- **The daemon (ADR-0010) owns fan-out** when present. The agent process must not own its own audit trail; the same logic must extend to disclosures.

The existing TS-SDK design — `parameters_preview` as a *plaintext signed field* — fails the second and third constraints. The chain commits to plaintext, so the receipt cannot be safely fanned out to a SIEM, and the field cannot be encrypted at rest without breaking signature verification.

## Decision

Operator-controlled, privacy-preserving by default, with **asymmetric encryption of the disclosure field inside the signed receipt body**. The emitter holds only the public key; the private key lives with the forensic responder / escrow holder. The chain commits to ciphertext.

### Naming

- Config knob: **`parameterDisclosure`** (renamed from `parameterPreview`).
- Receipt field: **`parameters_disclosure`** (renamed from the existing TS `parameters_preview`).

The previous names misdescribe ciphertext. "Preview" implies a glimpse; "raw" / "plain" imply plaintext. "Disclosure" is honest: the field discloses on demand, to the holder of the right key, and is opaque otherwise.

### Operator control

- The default for every channel is **hash-only**. Identical commitment via `parameters_hash` (already standard).
- Disclosure is opt-in via `parameterDisclosure` with the existing OpenClaw value space: `false | true | "high" | string[]`. (`"high"` defers to the taxonomy's risk classification; the array form is an explicit allowlist of action types.)
- The setting **MUST** live in operator config (env, on-disk config, or daemon config under ADR-0010), never in agent-supplied input. Reject any in-receipt or per-call agent override.

### Asymmetric encryption

- Emitter holds **only the forensic public key**.
- Private key lives with the forensic responder / escrow holder, separate from the encryptor.
- Encryptor genuinely cannot decrypt its own past disclosures — same trust property as ADR-0010 (the agent must not own its own audit trail).
- Verifiers verify the chain without holding any encryption key. Forensic responders, holding the private key, recover plaintext on demand.
- **Hard rule:** the Ed25519 signing key is never reused as an encryption key. Different purposes, different lifecycles. X25519 is the natural sibling for an X25519-class hybrid construction.

### Forward-compatible envelope shape

The disclosure field carries a structured envelope:

```jsonc
"parameters_disclosure": {
  "v": 1,                               // envelope schema version
  "alg": "...",                         // e.g. "hpke-x25519-aes256gcm-sha256"
  "recipients": [                       // length 1 in MVP; multi-recipient later
    { "kid": "...", "encap": "..." }    // alg-specific (e.g. HPKE encapsulated key)
  ],
  "nonce": "...",
  "ct": "..."                           // ciphertext over the parameters JSON
}
```

Single-recipient v1 ships with `recipients` length 1. Multi-recipient (HPKE-style envelope to N forensic public keys) lands later **without a format change**. Older verifiers reading newer receipts ignore unknown `alg` values gracefully and still verify the chain — they just cannot decrypt.

The exact `alg` string, AEAD primitive, and `kid` registry mechanism are deferred to a follow-up implementation ADR. What this ADR commits to is the envelope's *shape* and its forward-compatibility properties, because once a receipt is signed, its canonical-JSON bytes are permanent.

Cross-SDK serialisation of this envelope is load-bearing — all three SDKs must produce byte-identical canonical JSON (per ADR-0009).

### Modes

The same architecture serves three personas. No migration is required between them; only key custody changes.

| | Solo dev | Small team | Enterprise |
|---|---|---|---|
| **Public key (encrypt)** | Auto-generated on first run, stored next to signing key | Distributed to laptops via config or daemon-served | Daemon-served from key registry; baked into images |
| **Private key (decrypt)** | Same machine as public — operator owns both | Held by security lead, not on dev laptops | HSM / KMS, multi-recipient escrow (security + legal + corporate root) |
| **Storage** | Local SQLite | Local SQLite + optional remote sync | Pluggable: Postgres, S3, OTel exporters |
| **Fan-out** | None | Optional SIEM / shared dashboard | SIEM, archive, compliance store |
| **Decrypt UX** | `agent-receipts inspect <id>` reads local private key | Security lead runs same CLI with their key | Forensic responder retrieves private key from KMS, decrypts in IR tooling |
| **Code path** | Identical | Identical | Identical |

### Storage and fan-out

- **Storage adapters are opaque durability.** No adapter is required to know about encryption. SQLite, Postgres, S3, OTel exporters — all see the same signed-receipt blob. Pluggable storage and SIEM fan-out fall out for free.
- **Daemon owns fan-out** (per ADR-0010). The daemon dispatches signed receipts to local store and any configured sinks. SDK-direct mode keeps local-only behaviour.
- **Schema versioning.** Today's implicit `ALTER TABLE` migrations are acceptable for a hash-only world; introduce a `schema_version` row in the metadata table as a precondition to landing disclosures so we don't lose forensic data through a silent migration.

### Implementation phasing

This ADR's *architecture* is decided now (because the receipt format is permanent once signed). The *implementation* is sequenced behind real value to real personas:

- **Phase A — SDK-direct, solo-dev value.** `parameterDisclosure` config + auto-generated forensic key pair + basic CLI for key export / import. Pre-daemon.
- **Phase B — Daemon-owned (post-ADR-0010).** Daemon serves public keys, owns fan-out, and is the only process that briefly holds plaintext during encryption. Emitters become thin.
- **Phase C — Enterprise.** Multi-recipient HPKE, HSM / KMS adapters, pluggable remote stores, retention knobs, operator-facing key-management documentation.

Phase A receipts are forward-compatible with Phase B and C — no re-encryption, no migration.

## Consequences

### Positive

- Uniform answer to the most common forensic question, across every emitter.
- Operator-only control closes the "agent disables its own logging" footgun.
- The asymmetric construction matches ADR-0010's trust model: the encryptor cannot read its own past output, exactly as the agent cannot rewrite its own audit trail.
- Storage stays pluggable. Adapters never see plaintext and never inherit key-management responsibility.
- SIEM / OTel fan-out works trivially: the same signed receipt goes everywhere; the forensic private key gates disclosure mathematically, not configurationally. Trend-analysis sinks get hashes, action types, risk levels, timing, and decisions — never the payload.
- **Crypto-shredding is the GDPR right-to-erasure story.** Destroying the forensic private key (or a per-subject key, if scoped) makes ciphertext meaningless while the chain stays intact. Cleaner than tombstones in an immutable chain.
- The same architecture serves solo, team, and enterprise personas without migration — only key custody changes.

### Negative / explicitly accepted

- **Cross-SDK canonical shape becomes load-bearing.** The disclosure envelope must serialise byte-identically across TS / Py / Go (ADR-0009 territory).
- **Two keys to manage.** Operators now hold an Ed25519 signing key *and* a forensic key pair. Rotation, backup, escrow, and recovery stories all needed.
- **Old private keys must be retained forever.** Receipts are immutable; we cannot re-encrypt historical disclosures when the forensic private key rotates. Public key can rotate freely; private keys accumulate.
- **Verifier UX shifts.** Verification of the chain is unchanged, but forensic recovery now requires the private key. Document explicitly: signing-key holders cannot read disclosures; private-key holders cannot forge receipts.
- **Plaintext window in the encryptor.** The encryptor briefly holds plaintext between "receive parameters" and "encrypt + sign + ship". Daemon mode (ADR-0010) keeps that window out of the agent process; SDK-direct mode keeps it in the SDK process. Documented as the principal reason to prefer daemon mode in non-solo deployments.
- **GDPR / data-handling.** Operators handling PII inherit data-controller obligations even with crypto-shredding available. Surface prominently in docs, not just here.
- **Existing TS `parameters_preview` field is repurposed.** Plaintext-in-body is removed as a supported mode; the field is renamed to `parameters_disclosure` and now carries an envelope, not a string map. This is a behaviour-breaking change (likely a TS SDK major version bump). OpenClaw plugin config also migrates from `parameterPreview` to `parameterDisclosure` with a deprecation alias.
- **Retention is still needed.** Crypto-shredding handles confidentiality long-term, but operators may still want row TTL for storage cost reasons. In-scope to introduce a retention knob (default: keep forever, matching today).

## Alternatives considered

- **Always store raw plaintext.** Strongest forensics, worst default privacy posture. Rejected.
- **Never store raw payloads.** Strongest privacy, leaves the forensic question unanswered. Rejected.
- **Per-tool config without taxonomy integration.** Pushes risk classification onto every operator. Rejected in favour of taxonomy defaults (`"high"`) with explicit allowlist override.
- **Plaintext-in-body (TS SDK today).** Tamper-evident but blocks pluggable-storage encryption *and* SIEM fan-out (any sink seeing the receipt sees the payload). Rejected — superseded by encrypted-in-body.
- **Symmetric encryption (single shared key).** Rejected. The encryptor would be able to decrypt its own past output, breaking parity with ADR-0010's trust model. Also forces fragile key partitioning if SIEMs must be denied decryption capability.
- **Encryption at the storage adapter** (SQLCipher / Postgres TDE / S3 SSE-KMS). Each adapter reinvents key handling, plaintext crosses the adapter boundary, SIEM/telemetry fan-out needs separate redaction. Crypto-shredding only as good as the weakest adapter. Rejected — wrong layer.
- **Sidecar table outside the signed chain.** Avoids canonical-JSON entanglement and allows independent encryption / deletion, but the sidecar is not tamper-evident. Rejected; reserved as a future ADR if right-to-erasure pressure forces selective deletion beyond what crypto-shredding already provides.
- **Defense-in-depth (in-body AND adapter encryption).** Strongest, but doubles the operator's key-management surface. Out of scope for v1.
- **Wait until daemon (ADR-0010) ships.** The daemon is a deployment shift, not an architecture shift. Receipt format is permanent once signed, so the format and envelope must be settled now. Implementation phasing follows the daemon timeline (Phase A pre-daemon, Phase B post-daemon).

## Related ADRs

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — signing key strictly separated from forensic key pair.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — disclosure envelope must respect canonical JSON; field ordering and null-vs-omitted handling become verification concerns.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — this ADR explicitly does not extend SQLite-specific encryption; storage stays opaque.
- [ADR-0008 (response hashing and chain completeness)](./0008-response-hashing-and-chain-completeness.md) — same forensic-vs-privacy argument applies to response payloads; this ADR scopes itself to *parameters* and flags responses as the obvious follow-up.
- [ADR-0009 (canonicalisation profile)](./0009-canonicalization-and-schema-consistency.md) — the disclosure envelope shape is exactly the kind of cross-SDK consistency this ADR is about.
- [ADR-0010 (daemon process separation)](./0010-daemon-process-separation.md) — the daemon owns fan-out and the plaintext window; "operator-controlled" is a real boundary because of this ADR.
- [ADR-0011 (Zod runtime validation)](./0011-zod-for-runtime-validation.md) — the disclosure envelope schema must be added to the Zod store-load validation in the TypeScript SDK.
