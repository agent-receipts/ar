# Changelog

All notable changes to the Agent Receipt Protocol specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **BREAKING:** W3C VC type renamed from `AIActionReceipt` to `AgentReceipt`
- **BREAKING:** Schema file renamed from `action-receipt.schema.json` to `agent-receipt.schema.json`
- **BREAKING:** Spec document renamed from `action-receipt-spec-v0.1.md` to `agent-receipt-spec-v0.1.md`
- All example receipts updated to use `AgentReceipt` credential type

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
