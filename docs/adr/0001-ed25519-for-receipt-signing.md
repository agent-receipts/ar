# ADR-0001: Ed25519 for Receipt Signing

## Status

Accepted

## Context

The Agent Receipts protocol requires a digital signature algorithm for signing all receipts. Receipts form chains where each receipt references its predecessor, so key and signature sizes compound across the chain. The protocol also needs strong cross-language support since SDKs exist in Go, Python, and TypeScript, and verification performance matters when auditing large receipt chains.

We evaluated the following alternatives:

- **ECDSA (secp256k1 / P-256):** Widely deployed, but non-deterministic signatures introduce nonce reuse risk, which has caused real-world key compromise in other systems. Deterministic ECDSA (RFC 6979) mitigates this but adds implementation complexity.
- **RSA (2048/4096):** Ubiquitous in enterprise environments, but keys (256–512 bytes) and signatures (256–512 bytes) are an order of magnitude larger than Ed25519. This is prohibitive for receipt chains.
- **Ed448:** Offers a higher security margin (224-bit classical / ~112-bit quantum vs 128-bit classical / ~64-bit quantum for Ed25519) but has significantly less library support, larger keys (57 bytes) and signatures (114 bytes), and slower operations — without a compelling threat model to justify the trade-offs today.

Related: #20 (parent issue), #39.

## Decision

Use Ed25519 (RFC 8032) as the sole signature algorithm for all receipt signing in the Agent Receipts protocol.

Key reasons:

- **Deterministic signatures** — no nonce reuse risk, eliminating an entire class of implementation vulnerabilities present in ECDSA.
- **Compact keys (32 bytes) and signatures (64 bytes)** — critical for receipt chains where every byte compounds.
- **Fast verification** — important when auditing large receipt chains.
- **Excellent cross-language support** — available in Go stdlib (`crypto/ed25519`), libsodium, PyNaCl, and the Web Crypto API.
- **W3C VC ecosystem alignment** — Ed25519 is a first-class algorithm in the Verifiable Credentials ecosystem, which aligns with our envelope format and `Ed25519Signature2020` proof type.
- **No patent encumbrances.**
- **Designed for constant-time implementation** — the algorithm structure facilitates timing side-channel resistance, though this property ultimately depends on each library's implementation (see Security Considerations).

## Security Considerations

### Signature malleability

Ed25519 has known malleability concerns: some implementations accept non-canonical signatures where the S component is not fully reduced. All Agent Receipts SDK implementations MUST perform strict verification as specified in RFC 8032 §5.1.7, rejecting non-canonical signatures. This is especially important because we ship three SDK implementations (Go, Python, TypeScript) using different underlying libraries — a signature accepted by one SDK but rejected by another would break cross-language receipt verification.

### Canonicalization dependency

The security of receipt signatures depends on RFC 8785 (JSON Canonicalization Scheme) producing identical byte sequences across all implementations. If two SDKs canonicalize the same receipt differently, signatures will not verify cross-language. This is a real attack surface: any divergence in canonicalization could allow an attacker to present a receipt that verifies under one SDK but not another. Cross-language test vectors (see `sdk/py/tests/fixtures/ts_vectors.json`) mitigate this but are not a substitute for thorough fuzz testing of canonicalization edge cases.

### Hash function scope

This ADR covers only the signature algorithm. Receipt chain linkage uses SHA-256 for `previous_receipt_hash`, which has the same quantum-resistance limitations as Ed25519. The hash function choice should be addressed in a separate ADR or included when algorithm agility (#32) is designed.

### Encoding

Receipt `proofValue` uses multibase base64url encoding (`u` prefix) rather than the W3C Data Integrity default of base58btc (`z` prefix), as documented in spec §10.2. Encoding mismatches between implementations are a realistic source of cross-SDK verification failures. All SDKs must use base64url with no padding and the `u` multibase prefix.

### Key lifecycle

This ADR does not address key rotation, revocation, or compromise recovery. A compromised signing key can forge receipts that retroactively poison a chain. Key lifecycle management will be addressed separately (see spec §9.6) but is critical to the overall security of the protocol and should not be deferred indefinitely.

### Timing side-channels

The Ed25519 algorithm is designed to facilitate constant-time implementations, and the libraries used by our SDKs (Go `crypto/ed25519`, Python `cryptography`/OpenSSL, Node.js `crypto`) are believed to provide constant-time operations. However, this property is an implementation characteristic, not an inherent guarantee of the algorithm specification. SDK implementers should verify constant-time behavior when updating or replacing cryptographic dependencies.

## Known Risks

- **Not quantum-resistant.** Ed25519 provides ~128-bit classical security but only ~64-bit security against quantum attacks (Grover's algorithm on the underlying curve). This is acknowledged and tracked in #32 (algorithm agility). The planned algorithm agility mechanism will allow migration to a post-quantum algorithm when standards mature.
- **No algorithm agility in v0.1.** The current wire format hardcodes `Ed25519Signature2020` as the proof type with no version field or algorithm dispatch mechanism. Old verifiers will need a strategy for handling receipts signed with future algorithms. The algorithm agility design (#32) must address how v0.1 receipts are treated when new algorithms are introduced — at minimum, v0.1 receipts should be considered implicitly tagged as Ed25519.
- **Less ubiquitous in enterprise environments than RSA.** Adoption has grown substantially and Ed25519 is supported in all modern TLS and SSH implementations.
- **Single curve means no negotiation flexibility.** Mitigated by the planned algorithm agility mechanism, which will allow adding algorithms without breaking existing receipts.

## Consequences

- All SDKs (Go, Python, TypeScript) must implement Ed25519 signing and verification with strict RFC 8032 verification.
- Receipt envelope format is simpler — no algorithm negotiation fields needed initially.
- Receipt chains benefit from compact signatures, reducing storage and bandwidth overhead.
- Enterprise integrations that only support RSA will need a compatibility layer or must adopt Ed25519.
- Cross-language canonicalization and encoding conformance testing is a hard requirement, not optional.
- A future ADR will be needed to introduce algorithm agility (see #32) when post-quantum migration becomes necessary, covering both the signature algorithm and chain hash function.
