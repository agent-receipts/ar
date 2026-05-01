# Changelog

All notable changes to `@agnt-rcpt/sdk-ts` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [0.6.0] - 2026-05-01

### Breaking Changes

- **Renamed `parameters_preview` → `parameters_disclosure`** on the `Action`
  interface and its Zod schema. Per
  [ADR-0012](https://github.com/agent-receipts/ar/blob/main/docs/adr/0012-payload-disclosure-policy.md),
  "preview" misdescribed a permanent, signed field — receipts are durable, so
  any value placed there is a deliberate disclosure rather than a transient
  preview. The shape is unchanged (`Record<string, string>`); only the field
  name moved. **No deprecation alias is provided. Update all call sites
  before upgrading.** Pre-1.0 adoption is low and the rename is intentionally
  a clean break. Tracking issue:
  [#283](https://github.com/agent-receipts/ar/issues/283).

  Migration: rename every read/write of `action.parameters_preview` to
  `action.parameters_disclosure`. Previously written receipts that carry the
  old key under `.passthrough()` will still load, but new receipts MUST use
  the new key to round-trip through this SDK's typed surface.

### Features

- Add `parameters_disclosure` to the `Action` schema in the protocol spec
  (commits `2fd1837`, `5ef9d9a`, `e43cd06`).

### Bug Fixes

- Surface `verifyReceipt` errors in `ChainVerification.error` instead of
  swallowing them ([#294](https://github.com/agent-receipts/ar/pull/294)).
- Surface `hashReceipt` errors in `ChainVerification.error`
  ([#270](https://github.com/agent-receipts/ar/issues/270), commits `6a97840`,
  `bf030de`).
- Validate receipt schema on load from store, preserve unknown fields, tighten
  validator types, preserve `Error.cause`, and render the root path on parse
  failures ([#170](https://github.com/agent-receipts/ar/issues/170), commits
  `2db99c6`, `b273e50`, `01f5745`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Tests

- Add `parameters_disclosure` cross-language test vector in
  `cross-sdk-tests/` (commit `60bbe51`).

## [0.5.0] - 2026-04-27

### Added

- `parameters_preview?: Record<string, string>` field on the `Action` interface.
  An operator-controlled, additive map of field name → stringified value that
  sits alongside the existing `parameters_hash`. The hash continues to cover
  the full parameter set; the preview exists for human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `parameters_preview` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed allowlist
  and MUST NOT populate this field from raw tool arguments. The SDK does not
  auto-populate or validate this field; enforcement lives outside the SDK
  today (typically at the proxy/operator layer). Taxonomy-level allowlist
  support is tracked in
  [#258](https://github.com/agent-receipts/ar/issues/258).
  Treat it the same way you would treat a log line that ships to long-term
  storage: never include secrets, credentials, tokens, PII, or any field
  whose value you have not deliberately classified as safe to retain.
