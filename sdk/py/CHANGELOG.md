# Changelog

All notable changes to `agent-receipts` (Python SDK) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [0.9.0a2] - 2026-05-22

Re-cut of the v0.3.0 pre-release after fixing the `publish-py.yml`
event-type filter ([#518](https://github.com/agent-receipts/ar/pull/518)).
No source changes vs `0.9.0a1`; `0.9.0a1` was tagged but never reached
PyPI because the publish workflow only listened on
`release.types: [published]` and prereleases fire `prereleased`.

Skip `0.9.0a1` — install `agent-receipts==0.9.0a2`.

## [0.9.0a1] - 2026-05-22

First pre-release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/ar/issues/280).

### Breaking Changes

- **`Action.parameters_disclosure` shape changed** to the HPKE asymmetric encryption envelope. Was `dict[str, str] | None`, now `DisclosureEnvelope | None`. Downstream code that constructed the legacy flat-map will fail Pydantic validation. See [#505](https://github.com/agent-receipts/ar/pull/505).

### Added

- **`encrypt_disclosure` / `decrypt_disclosure` / `generate_forensic_key_pair`** ([#494](https://github.com/agent-receipts/ar/pull/494)) — RFC 9180 HPKE base-mode helpers (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM) for the v1 disclosure envelope. Hand-rolled on `pyca/cryptography` (no new top-level deps).
- **`Action.peer_credential`** — typed OS-attested peer process metadata (`platform`, `pid`, optional `uid`/`gid`/`exe_path`).
- **`Action.emitter_metadata`** — daemon-observed emitter-side metadata, currently `drop_count`.
- **Cross-SDK live-emit invariant test** ([#515](https://github.com/agent-receipts/ar/pull/515)).
- **`typing_extensions.TypedDict` migration** ([#505](https://github.com/agent-receipts/ar/pull/505)) — Pydantic v2 cannot introspect stdlib `typing.TypedDict` on Python < 3.12.

### Changed

- **`VERSION` constant is `"0.3.0"`** — receipts emitted via `create_receipt()` now stamp the v0.3.0 schema label.
- The typed `AgentReceipt` model only accepts the envelope shape on `parameters_disclosure`. Legacy v0.2.x flat-map receipts will fail `AgentReceipt(**raw_json)` — verifiers ingesting legacy receipts must use `hash_receipt(raw_dict)` and inline signature verification.

## [0.8.0] - 2026-05-15

### Changed

- No SDK code changes. Version bump to maintain lockstep with the coordinated v0.8.0 release.

## [0.8.0a2] - 2026-05-10

### Changed

- No SDK code changes; version bump to maintain lockstep across the coordinated
  release (daemon process separation cutover). Releases as part of the daemon
  refactor work (ADR-0010, [#236](https://github.com/agent-receipts/ar/issues/236)).

### Improved

- `VERSION` now derived from package metadata at import time via
  `importlib.metadata.version()`, making `pyproject.toml` the single source
  of truth and eliminating version drift (closes [#345](https://github.com/agent-receipts/ar/issues/345)).

## [0.8.0a1] - 2026-05-09

### Added

- Fire-and-forget emitter for forwarding tool-call events to the
  `agent-receipts-daemon` Unix socket (ADR-0010, [#236](https://github.com/agent-receipts/ar/issues/236)).
  No crypto, no canonicalisation — the daemon handles those operations.

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
