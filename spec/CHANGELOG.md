# Changelog

All notable changes to the Agent Receipt Protocol specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **BREAKING:** W3C VC type renamed from `AIActionReceipt` to `AgentReceipt`
- **BREAKING:** Schema file renamed from `action-receipt.schema.json` to `agent-receipt.schema.json`
- **BREAKING:** Spec document renamed from `action-receipt-spec-v0.1.md` to `agent-receipt-spec-v0.1.md`
- All example receipts updated to use `AgentReceipt` credential type

## [0.2.1] - 2026-04-22

### Changed
- **Field rename (schema-and-spec only):** `validFrom` → `issuanceDate`. All three SDKs have always emitted `issuanceDate` (VC 1.x naming); the schema is now aligned. No wire-format change for any existing receipt. See ADR-0009.
- **Optional-nullable types tightened:** `outcome.error`, `authorization.grant_ref`, and `action.trusted_timestamp` no longer declare `null` in their schema type. These fields MUST be absent (not `null`) when not applicable. The sole remaining nullable type in the schema is `chain.previous_receipt_hash` (required-nullable).
- `version` field now accepts `"0.1.0"`, `"0.2.0"`, or `"0.2.1"`. Verifiers MUST accept all three.

### Added
- Spec §7.1.1: normative null/optional field handling rule — required-nullable fields MUST be emitted with their value (including explicit `null`); optional fields MUST NOT be emitted when null or absent. Closes #85 at the spec level.
- `cross-sdk-tests/canonicalization_vectors.json`: shared canonicalisation test vectors covering UTF-16 key-sort edge cases, ES6 number boundaries, RFC 8259 string escaping, null normalisation, and signature preservation.
- ADR-0009: records the two spec-level decisions (VC field name commitment, null rule) and the signature-preservation invariant for existing receipts.

### Upgrade notes

**Issuers and verifiers:** No action required for existing receipts. All shipped 0.1.0 and 0.2.0 receipts already use `issuanceDate` and none emit `null` on optional fields, so the wire format is unchanged. Upgrade to `"version": "0.2.1"` when emitting new receipts to signal conformance to the null-rule and the tightened schema.

## [0.2.0] - 2026-04-22

### Added
- `outcome.response_hash` — optional `sha256:`-prefixed hash of the RFC 8785 canonical JSON of the server's response, computed after secret redaction (redact → hash → sign). Issuers populate when emitting responses they wish to commit to; verifiers recompute when the response body is available and fail on mismatch. When the response body is absent the verifier notes "response hash present, body not supplied" and continues. Absence of the field is not a failure.
- `chain.terminal` — optional field restricted to the constant `true`. Marks the last receipt in a chain as closed. Explicit `false` is schema-invalid; absence means no claim. An automatic "receipt after terminal" integrity check invalidates any receipt that appears after a terminal receipt in the verified input sequence, regardless of linkage or caller parameters.
- `VerifyChain` gains three optional parameters across all SDKs — `ExpectedLength`, `ExpectedFinalHash`, `RequireTerminal` — for out-of-band and in-band truncation detection. When unsupplied, behaviour is identical to v0.1.0.
- Spec §7.3.1: normative language stating that chain verification does **not** detect tail truncation by default, documenting the three available mitigations, and stating the detection floor.
- Spec §7.3.2: normative language defining the unconditional receipt-after-terminal integrity check.

### Changed
- `version` field now accepts both `"0.1.0"` and `"0.2.0"`. Verifiers MUST accept both values. All new receipts SHOULD use `"0.2.0"`.

### Upgrade notes

**Issuers:** No action required to remain protocol-valid. To commit to the server's response, redact the response body, canonicalize (RFC 8785), hash (SHA-256), and populate `outcome.response_hash` before signing. To mark a chain as closed, set `chain.terminal: true` on the final receipt — omit the field entirely otherwise (never emit `false`).

**Verifiers:** No breaking changes. `VerifyChain` with no new parameters is identical to v0.1.0 behaviour. Pass `RequireTerminal: true` for chains that must close cleanly. Pass `ExpectedFinalHash` when you maintain an external audit record of chain state.

## [0.1.0] - 2026-03-31

### Added
- Core protocol specification (§1–§10)
- Action Receipt schema as W3C Verifiable Credential with `AIActionReceipt` type
- Ed25519Signature2020 signing and verification
- Receipt chain model with SHA-256 hash linking and sequence numbering
- Delegation model for multi-agent scenarios with parent chain references
- Reversal receipt model with `outcome.reversal_of` field
- Normative chain issuer rule: one issuer per chain, delegation creates new chains
- Action taxonomy with six domains: filesystem, system, communication, document, financial, data
- Risk level classification: low, medium, high, critical (no-downgrade rule)
- `unknown` action type fallback with mandatory `action.target.system`
- Custom action type support via reverse-domain prefixes
- JSON Schema (Draft 2020-12) for receipt validation
- Taxonomy JSON Schema for action type definitions
- Privacy-preserving design: parameters hashed, never stored in plaintext
- Optional RFC 3161 trusted timestamps
- Non-normative intent field guidance (conversation_hash, reasoning_hash)
- End-to-end receipt verification algorithm (§7.8)
- CI workflow for JSON syntax and schema validation
- AGENTS.md for AI coding agent context
- Open questions documented in §9 (concurrent chains, DID methods, batched receipts, etc.)
