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
| [ADR-0007](0007-did-method-strategy.md) | DID Method Strategy | Proposed |
| [ADR-0008](0008-response-hashing-and-chain-completeness.md) | Response Hashing and Chain Completeness | Accepted |

## References

- [ADR GitHub org](https://adr.github.io/)
- [AWS ADR best practices](https://aws.amazon.com/blogs/architecture/master-architecture-decision-records-adrs-best-practices-for-effective-decision-making/)
- [adr-tools CLI](https://github.com/npryce/adr-tools)
