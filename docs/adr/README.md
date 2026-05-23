# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Agent Receipts project.

ADRs capture the context, decision, and consequences of architecturally significant choices. They help contributors and AI agents understand not just *what* was chosen but *why*.

## Template

Use `0000-template.md` as the starting point for new ADRs. Name each new ADR file with a sequential 4-digit prefix (for example, `0001-my-decision.md`, `0002-another-decision.md`, etc.). In the ADR content, use the same number in the header as `ADR-0001`, `ADR-0002`, and so on. The ADR number in the header should always match the filename prefix.

## Index

<!-- Add entries here as ADRs are created -->

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-0001](0001-ed25519-for-receipt-signing.md) | Ed25519 for Receipt Signing | Accepted |
| [ADR-0002](0002-rfc8785-json-canonicalization.md) | RFC 8785 for JSON Canonicalization | Accepted |
| [ADR-0003](0003-w3c-vc-envelope-format.md) | W3C Verifiable Credentials as the Receipt Envelope | Accepted |
| [ADR-0004](0004-sqlite-for-local-receipt-storage.md) | SQLite for Local Receipt Storage | Accepted |
| [ADR-0005](0005-independent-sdk-implementations.md) | Independent SDK Implementations (Not Code Generation) | Accepted |
| [ADR-0006](0006-yaml-for-policy-rules.md) | YAML for Policy Rule Configuration (mcp-proxy) | Accepted |
| [ADR-0007](0007-did-method-strategy.md) | DID Method Strategy | Accepted (decision only; Phase A scoped, not started) |
| [ADR-0008](0008-response-hashing-and-chain-completeness.md) | Response Hashing and Chain Completeness | Accepted |
| [ADR-0009](0009-canonicalization-and-schema-consistency.md) | Canonicalisation Profile and VC Field Name Commitment | Accepted |
| [ADR-0010](0010-daemon-process-separation.md) | Daemon Process Separation for Signing and Storage | Accepted |
| [ADR-0011](0011-zod-for-runtime-validation.md) | Zod for runtime schema validation | Accepted |
| [ADR-0012](0012-payload-disclosure-policy.md) | Payload Disclosure Policy (`parameterDisclosure`) | Accepted (partial impl; plaintext opt-in shipped, envelope pending) |
| [ADR-0013](0013-claude-code-hook-channel.md) | claude_code_hook Emission Channel | Accepted (Phase A shipped in `hook/` v0.10.0) |
| [ADR-0014](0014-codex-hook-channel.md) | codex_hook Emission Channel | Proposed (substrate shipped, Codex reader pending) |
| [ADR-0015](0015-key-rotation-byok-anchoring.md) | Key Rotation, BYOK Abstraction, and External Anchoring | Accepted (Phase A in progress) |
| [ADR-0016](0016-mcp-proxy-audit-encryption.md) | Audit Store Encryption at Rest (mcp-proxy) | Accepted |
| [ADR-0017](0017-central-receipt-hub.md) | Central Receipt Hub and External Anchoring | Accepted |
| [ADR-0018](0018-signer-abstraction-and-cloud-agnostic-keyprovider-design.md) | Signer Abstraction and Cloud-Agnostic KeyProvider Design | Accepted |
| [ADR-0019](0019-protocol-integrity-gaps-and-mitigations.md) | Protocol Integrity Gaps and Mitigations | Proposed |
| [ADR-0020](0020-emitter-abstraction-and-remote-receipt-delivery.md) | Emitter Abstraction and Remote Receipt Delivery | Accepted |

## References

- [ADR GitHub org](https://adr.github.io/)
- [AWS ADR best practices](https://aws.amazon.com/blogs/architecture/master-architecture-decision-records-adrs-best-practices-for-effective-decision-making/)
- [adr-tools CLI](https://github.com/npryce/adr-tools)
