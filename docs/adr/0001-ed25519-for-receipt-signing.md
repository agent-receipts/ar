# ADR-0001: Ed25519 for Receipt Signing

## Status

Proposed

## Context

The Agent Receipts protocol requires a digital signature algorithm for signing all receipts. Receipts form chains where each receipt references its predecessor, so key and signature sizes compound across the chain. The protocol also needs strong cross-language support since SDKs exist in Go, Python, and TypeScript, and verification performance matters when auditing large receipt chains.

We evaluated the following alternatives:

- **ECDSA (secp256k1 / P-256):** Widely deployed, but non-deterministic signatures introduce nonce reuse risk, which has caused real-world key compromise in other systems. Deterministic ECDSA (RFC 6979) mitigates this but adds implementation complexity.
- **RSA (2048/4096):** Ubiquitous in enterprise environments, but keys (256–512 bytes) and signatures (256–512 bytes) are an order of magnitude larger than Ed25519. This is prohibitive for receipt chains.
- **Ed448:** Offers a higher security margin (224-bit vs 128-bit) but has significantly less library support, larger keys (57 bytes) and signatures (114 bytes), and slower operations — without a compelling threat model to justify the trade-offs.

Related: #20 (parent issue), #39.

## Decision

Use Ed25519 (RFC 8032) as the sole signature algorithm for all receipt signing in the Agent Receipts protocol.

Key reasons:

- **Deterministic signatures** — no nonce reuse risk, eliminating an entire class of implementation vulnerabilities present in ECDSA.
- **Compact keys (32 bytes) and signatures (64 bytes)** — critical for receipt chains where every byte compounds.
- **Fast verification** — important when auditing large receipt chains.
- **Excellent cross-language support** — available in Go stdlib (`crypto/ed25519`), libsodium, PyNaCl, and the Web Crypto API.
- **W3C VC ecosystem alignment** — Ed25519 is a first-class algorithm in the Verifiable Credentials ecosystem, which aligns with our envelope format.
- **No patent encumbrances.**
- **Resistant to timing side-channel attacks** by design.

Known risks:

- **Not quantum-resistant.** This is acknowledged and tracked in #32 (algorithm agility). The planned algorithm agility mechanism will allow migration to a post-quantum algorithm when standards mature.
- **Less ubiquitous in enterprise environments than RSA.** Adoption has grown substantially and Ed25519 is supported in all modern TLS and SSH implementations.
- **Single curve means no negotiation flexibility.** Mitigated by the planned algorithm agility mechanism, which will allow adding algorithms without breaking existing receipts.

## Consequences

- All SDKs (Go, Python, TypeScript) must implement Ed25519 signing and verification.
- Receipt envelope format is simpler — no algorithm negotiation fields needed initially.
- Receipt chains benefit from compact signatures, reducing storage and bandwidth overhead.
- Enterprise integrations that only support RSA will need a compatibility layer or must adopt Ed25519.
- A future ADR will be needed to introduce algorithm agility (see #32) when post-quantum migration becomes necessary.
