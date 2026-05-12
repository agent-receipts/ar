# ADR-0007: DID Method Strategy

## Status

Accepted (2026-05-12) — Phase A only. Phase B (`did:web` resolution) and the pluggable resolver interface are designed but not yet scheduled. See *Implementation phasing* below.

## Context

The Agent Receipts protocol uses Decentralized Identifiers (DIDs) for both agent identity (`issuer.id`) and human principal identity (`credentialSubject.principal.id`). The current spec (v0.1) requires DIDs in these fields but does not mandate a specific DID method — the examples use `did:agent:` and `did:user:`, which are illustrative placeholders with no defined resolution mechanism. A verifier cannot resolve these identifiers to public keys without out-of-band knowledge.

This is explicitly called out as open question §9.6 in the spec: the protocol needs a DID method strategy that balances simplicity for early adopters against production requirements like key rotation, organizational anchoring, and human-readable identity.

We evaluated the following approaches:

- **`did:key` only.** The public key *is* the identifier (e.g., `did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP`). No resolution infrastructure needed — the DID is self-describing. This is the simplest possible approach and is already sufficient for local signing and verification. However, `did:key` has no mechanism for key rotation (rotating the key changes the identifier), no organizational anchoring (nothing ties the DID to a domain, company, or agent platform), and identifiers are opaque base58 strings with no human meaning. For a protocol that produces long-lived audit records, the inability to rotate a compromised key without breaking chain identity is a significant limitation.

- **Default `did:key`, recommend `did:web` for production.** `did:web` anchors identity to a DNS domain (e.g., `did:web:agents.example.com:claude-instance-abc123`), providing organizational anchoring and human-readable identifiers. The DID Document is a JSON file hosted at a well-known HTTPS URL, so resolution is just an HTTP GET — no blockchain or distributed ledger required. `did:web` supports key rotation (update the DID Document) and can express verification relationships, service endpoints, and controller hierarchies. The trade-off is a dependency on DNS and HTTPS infrastructure, which introduces a trust anchor external to the protocol. This two-tier approach lets developers start with `did:key` and upgrade to `did:web` when they need production identity.

- **Pluggable DID method resolution.** Define a DID resolution interface in each SDK (Go, Python, TypeScript) and let integrators supply their own resolver for any DID method. This maximizes flexibility — an enterprise could use `did:web`, a blockchain project could use `did:ion` or `did:ethr`, a research group could use `did:peer`. The cost is complexity: each SDK must define and document a resolver interface, and cross-implementation interoperability depends on both parties supporting the same DID method. Without a default, two independent deployments may not be able to verify each other's receipts.

- **`did:peer` for ephemeral agent identity.** `did:peer` is designed for pairwise relationships and does not require any resolution infrastructure — peers exchange DID Documents directly. This could work for agent-to-agent scenarios but does not support the public verifiability that audit trails require. A third-party auditor cannot resolve a `did:peer` identifier without the peer relationship context.

- **Custom `did:agent` method.** Define a new DID method specific to agent identity, potentially backed by an agent registry (e.g., MolTrust). This provides maximum control over the identity model but requires specifying, implementing, and maintaining a new DID method — a significant undertaking that would delay adoption and fragment the DID ecosystem further.

Related: #20 (parent issue), spec §9.6 (open question #6), ADR-0001 (key lifecycle), ADR-0003 (DID ecosystem coupling risk).

## Decision

A tiered approach:

1. **`did:key` as the default.** All SDKs ship with built-in `did:key` generation and resolution. This is the zero-configuration path: generate an Ed25519 key pair, derive the `did:key` identifier, and start signing receipts. No external infrastructure required.

2. **`did:web` as the recommended production method.** For deployments that need organizational anchoring, key rotation, or human-readable identity, the protocol recommends `did:web`. SDKs provide built-in `did:web` resolution (HTTPS fetch of the DID Document). Agent platforms and enterprises host DID Documents at their domain.

3. **Pluggable resolver interface for other methods.** SDKs expose a DID resolution interface that integrators can implement for any DID method. The protocol does not endorse or require any method beyond `did:key` and `did:web`, but does not prevent others.

### Resolved questions

- **Production tier.** `did:web` is the recommended production method. Its DNS dependency is accepted as the cost of organizational anchoring; `did:tdw` is noted as a future upgrade path if the DNS-trust footprint becomes a blocker, but not adopted now (additional complexity, smaller adopter base).
- **Conformance.** Conformant implementations MUST support `did:key` and SHOULD support `did:web`. Other methods are pluggable but not required for interop.
- **Key rotation interaction.** Covered by [ADR-0015](./0015-key-rotation-byok-anchoring.md): `proof.verificationMethod` carries the issuer's stable DID URL across rotations; the rotation-event witness chain plus DID resolution together let verifiers recover the key valid at a receipt's `issuanceDate`. This ADR no longer holds the rotation-semantics question open.
- **`did:peer` for delegation.** Deferred. The delegation model (spec §7.6) is not yet in scope for implementation; revisit when delegation lands.
- **`did:tdw`.** Deferred as above — interesting if `did:web` trust assumptions prove inadequate in real deployments, not a v1 concern.

## Implementation phasing

- **Phase A (now).** All SDKs implement `did:key` generation and resolution as a built-in capability. Existing `did:agent:` / `did:user:` placeholders in examples and test vectors are replaced with `did:key` equivalents. The protocol's verification algorithm is updated to require `did:key` resolution as an explicit step.
- **Phase B (deferred).** `did:web` resolution lands in all SDKs along with the pluggable resolver interface. Trigger conditions: (a) a production deployment needs organizational anchoring; (b) a verifier needs to validate receipts whose issuer has rotated keys (ADR-0015 Phase A reaches the daemon); (c) `did:web` is required for cross-org interoperability with a named consumer.
- **Phase C (deferred).** Verifier-side DID Document caching/pinning, historical resolution for long-lived receipts, and `did:tdw` evaluation.

## Security Considerations

### Key-DID binding

With `did:key`, the binding between key and identifier is cryptographic and self-evident — the DID *is* the key. With `did:web`, the binding depends on the integrity of the HTTPS-hosted DID Document. A compromised web server can substitute a different public key, allowing forged receipts that appear to come from a legitimate agent. TLS and DNSSEC mitigate but do not eliminate this risk. The protocol should specify whether receipt verifiers must pin or cache DID Documents, and how to handle DID Document changes during chain verification.

### DID Document availability

`did:web` resolution depends on the hosting domain being available. If the domain goes offline, verifiers cannot resolve the DID and cannot verify receipts. For long-lived audit records, this is a significant concern — a receipt may need to be verifiable years after the issuing organization changes domains or ceases operations. Caching strategies, DID Document archival, or a fallback to embedded public keys may be necessary.

### Cross-method interoperability

If the protocol supports multiple DID methods, two deployments using different methods may produce receipts that the other cannot verify without adding a new resolver. The protocol should specify a minimum interoperability baseline — likely `did:key` — to ensure any conformant verifier can verify any conformant receipt at the base tier.

### Identifier correlation

`did:key` identifiers are derived from public keys, so the same key always produces the same DID. This enables cross-chain and cross-service correlation of agent activity. For privacy-sensitive deployments, this may be undesirable. `did:peer` or per-relationship `did:key` identifiers could mitigate correlation, but at the cost of complicating chain verification and auditor access.

## Known Risks

- **`did:web` trust model.** `did:web` inherits DNS and TLS trust assumptions. An attacker who controls the domain can forge the DID Document. This is fundamentally different from the self-certifying model of `did:key`. The protocol must be explicit about this trust boundary.
- **DID method fragmentation.** If the ecosystem fragments across many DID methods, cross-deployment verification becomes impractical. A clear default with a pluggable escape hatch is the mitigation.
- **Spec maturity.** `did:web` is a registered DID method with broad adoption but is still evolving. `did:tdw` is newer and less proven. Committing to a specific method ties the protocol to that method's evolution.
- **Key rotation complexity.** Key rotation with `did:web` requires careful coordination between the DID Document, the receipt chain, and any verifier caching. Getting this wrong could either lock agents into permanent keys (defeating the purpose) or break chain verification (defeating the protocol).

## Consequences

- All SDKs (Go, Python, TypeScript) must implement `did:key` generation and resolution as a built-in capability.
- SDKs should define a DID resolver interface to support pluggable methods.
- The spec must update §9.6 to replace the placeholder `did:agent:` / `did:user:` identifiers with guidance on `did:key` (and optionally `did:web`) usage.
- Existing examples and test vectors using `did:agent:` identifiers will need updating once a decision is finalized.
- Key rotation semantics for receipt chains must be specified — either in this ADR or a companion ADR — before `did:web` can be recommended for production use.
- Cross-SDK DID resolution test vectors are needed to ensure all three implementations resolve the same `did:key` identifiers to the same public keys.
- The verification algorithm (spec §7.1, §7.3) must be updated to include DID resolution as an explicit step with defined error handling.
