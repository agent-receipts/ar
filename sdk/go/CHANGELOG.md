# Changelog

All notable changes to `github.com/agent-receipts/ar/sdk/go` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [0.6.0] - 2026-05-01

### Features

- Add `ParametersDisclosure map[string]string` field to the `Action` struct,
  matching the spec change in [ADR-0012](https://github.com/agent-receipts/ar/blob/main/docs/adr/0012-payload-disclosure-policy.md)
  (commit `3d51d44`). Operator-controlled, additive map of field name →
  stringified value that sits alongside `ParametersHash`. The hash continues
  to cover the full parameter set; `ParametersDisclosure` exists for
  human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `ParametersDisclosure` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed
  allowlist and MUST NOT populate this field from raw tool arguments.

### Bug Fixes

- Surface `HashReceipt` errors in `VerifyChain` instead of silently returning
  `HashLinkValid: false` (indistinguishable from tampering). On hash-compute
  failure, `ChainVerification.Error` is now populated with the failing index
  and reason, and the function returns early — mirroring the existing
  signature-error pattern
  ([#173](https://github.com/agent-receipts/ar/issues/173), commits `675e8f4`,
  `2b5a1ce`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Tests

- Add `parameters_disclosure` cross-language test vector in
  `cross-sdk-tests/` (commit `60bbe51`).
- Add `TestVerifyChainSurfacesHashError` covering the new hash-error branch
  in `VerifyChain` (commit `675e8f4`).
