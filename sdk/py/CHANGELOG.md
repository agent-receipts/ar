# Changelog

All notable changes to `agent-receipts` (Python SDK) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [0.5.0] - 2026-05-01

### Hash compatibility note

This release contains a canonicalization fix that changes the SHA-256 receipt
hash for receipts whose JSON exercises the affected edge cases (non-BMP UTF-16
sort keys, numbers near the ES6 fixed/exp boundaries, optional `null`
fields). Receipts created with v0.4.0 will still verify their own signatures,
but their stored hash may not match a freshly recomputed hash under v0.5.0.
Re-hash existing chains if you store hashes outside the receipt payload. See
ADR-0009 for the canonicalization profile.

### Features

- Add `parameters_disclosure: dict[str, str] | None` to the `Action` model,
  matching the spec change in [ADR-0012](https://github.com/agent-receipts/ar/blob/main/docs/adr/0012-payload-disclosure-policy.md)
  (commits `8caaba0`, `9fde2d5`). Operator-controlled, additive map of field
  name → stringified value that sits alongside `parameters_hash`. The hash
  continues to cover the full parameter set; `parameters_disclosure` exists
  for human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `parameters_disclosure` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed
  allowlist and MUST NOT populate this field from raw tool arguments. The SDK
  does not auto-populate or validate this field; enforcement lives outside
  the SDK today (typically at the proxy/operator layer). Treat it the same
  way you would treat a log line that ships to long-term storage: never
  include secrets, credentials, tokens, PII, or any field whose value you
  have not deliberately classified as safe to retain.

### Bug Fixes

- **Canonicalization (ADR-0009):** fix UTF-16 sort key to use 16-bit code
  units (was sorting little-endian bytes), rewrite `_canonicalize_number` to
  match ES6 fixed/exp notation boundaries (1e-6 / 1e21) without `repr()`
  rounding drift, and uniformly strip optional `null` fields while preserving
  required-nullable `previous_receipt_hash`
  ([#86](https://github.com/agent-receipts/ar/issues/86), commit `70426b7`).
  See the **Hash compatibility note** above.
- Use `setdefault` so `previous_receipt_hash` is actually attached when
  building a chained receipt (commit `532b7f7`).
- Cover `-0.0` in number canonicalization, fix encoding/E501, drop dead code
  (commit `d252ad6`).
- Surface `verify_receipt` errors in `ChainVerification.error` instead of
  swallowing them ([#295](https://github.com/agent-receipts/ar/pull/295)).
- Surface `hash_receipt` errors in `ChainVerification.error` (commit
  `0b87ef4`).
- Spec: align `proofValue` encoding to base64url throughout, tighten the
  schema pattern, fix inline placeholders, and use 86-char base64url
  placeholder values in all examples (commits `fa0db6b`, `79f7301`,
  `0839e81`).

### Internal

- Narrow `Any` types in `_strip_optional_nulls` to satisfy pyright (commit
  `fd4c3d1`).

### Tests

- Add cross-SDK canonicalization vector test runner and populate
  `cross-sdk-tests/canonicalization_vectors.json` (commit `70426b7`).
- Cover `expected_final_hash` hash-error branch and fix docstring (commit
  `8c80fc5`).
- Add `parameters_disclosure` cross-language test vector (commit `60bbe51`).

### Documentation

- ADR-0009: canonicalisation profile + `issuanceDate` commitment (commits
  `dbb88fb`, `1511551`, `0d88ec7`, `ea24c49`).

### Dependencies

- Bump the `uv` group in `sdk/py/` (4 updates, commit `92cfeb7`).
