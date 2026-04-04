---
applyTo: "**"
---

# General review guidelines

This is the Agent Receipts monorepo — cryptographically signed audit trails for AI agent actions.

## Security

- Flag any real private keys, secrets, or credentials in the diff.
- Ed25519 is the only supported signing algorithm. Flag any introduction of alternative or weaker schemes.
- Parameters in receipts must be hashed (SHA-256), never stored in plaintext. Flag any plaintext parameter storage.
- Flag any changes to `.github/workflows/` — these require explicit maintainer review.

## Cross-SDK consistency

- Receipt output must be byte-identical across Go, TypeScript, and Python SDKs.
- Changes to receipt creation, signing, hashing, or canonical JSON in any SDK should be flagged if there are no corresponding cross-language test updates.

## Code quality

- Flag unused code, dead imports, and breadcrumb comments ("moved to X", "removed").
- Prefer first-principles fixes over bandaids.
- Flag any `TODO` or `FIXME` comments that don't reference an issue number.
