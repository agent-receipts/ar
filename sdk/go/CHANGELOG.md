# Changelog

All notable changes to `github.com/agent-receipts/ar/sdk/go` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [Unreleased]

### Changed

- **`emitter.DefaultSocketPath()` macOS default is now HOME-based** ([#545](https://github.com/agent-receipts/ar/issues/545)). macOS resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. TMPDIR is not inherited by GUI-spawned subprocesses (e.g., MCP servers launched by Claude Desktop), which broke the daemon ↔ emitter handshake silently. HOME is preserved across every supported spawn context, so both sides of the IPC now resolve to the same path regardless of how they were started. Linux defaults are unchanged. AGENTRECEIPTS_SOCKET continues to take precedence — users who relied on TMPDIR redirection on macOS should switch to it.
- **Platform-specific socket resolution split into build-tagged files** (`socketpath_darwin.go`, `socketpath_linux.go`, `socketpath_other.go`). The public `DefaultSocketPath()` API is unchanged.

## [0.11.0] - 2026-05-22

First stable release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/ar/issues/280). Graduates `0.11.0-alpha.1` after the end-to-end alpha pass in [#519](https://github.com/agent-receipts/ar/issues/519). No source changes since `0.11.0-alpha.1`; see that entry below for the full v0.3.0 surface.

## [0.11.0-alpha.1] - 2026-05-22

First pre-release of the v0.3.0 spec migration (ADR-0012 Phase A). Tracked in [#280](https://github.com/agent-receipts/ar/issues/280).

### Breaking Changes

- **`Action.ParametersDisclosure` type changed** from `map[string]string` to `*DisclosureEnvelope` ([#506](https://github.com/agent-receipts/ar/pull/506)). Per ADR-0012 / spec v0.3.0 ([#496](https://github.com/agent-receipts/ar/pull/496)), the field now carries the HPKE asymmetric encryption envelope. Downstream code that wrote the legacy flat-map shape will not compile.

### Added

- **`EncryptDisclosure` / `DecryptDisclosure` / `GenerateForensicKeyPair`** ([#468](https://github.com/agent-receipts/ar/pull/468)) — RFC 9180 HPKE base-mode helpers (DHKEM(X25519) + HKDF-SHA256 + AES-256-GCM) via `cloudflare/circl`.
- **`Action.PeerCredential` struct** — typed OS-attested peer process metadata. Field widths match POSIX (`int32` for PID, `uint32` for UID/GID).
- **`Action.EmitterMetadata` struct** — daemon-observed emitter-side metadata, currently `DropCount`.
- **Cross-SDK live-emit invariant test** ([#515](https://github.com/agent-receipts/ar/pull/515)).

### Changed

- **`Version` constant bumped from `"0.2.0"` to `"0.3.0"`** ([#515](https://github.com/agent-receipts/ar/pull/515)).
- Legacy v0.2.x flat-map `parameters_disclosure` receipts no longer round-trip through `receipt.AgentReceipt`. Verifiers ingesting legacy receipts must use `map[string]any` — pattern in `sdk/go/receipt/canonicalization_vectors_test.go::TestParametersDisclosureReceipt`.

### Known issues

- `PeerCredential.UID` and `PeerCredential.GID` are `uint32` with `omitempty`, silently dropping UID=0 / GID=0 (root). Tracked in [#511](https://github.com/agent-receipts/ar/issues/511).

## [0.10.0] - 2026-05-19

### Added

- **Issuer/operator identity fields on emitted frames** ([#461](https://github.com/agent-receipts/ar/pull/461)):
  New `Identity` type and `WithIdentity()` constructor option let callers stamp
  `issuer_name`, `issuer_model`, `operator_id`, and `operator_name` on every
  emitted frame. Per-event fields on `Event` take precedence over the
  emitter-level defaults set via `WithIdentity`. The emitter validates identity
  fields before marshalling: `operator_name` requires `operator_id`, and each
  field is capped at 256 bytes (`MaxIdentityFieldLen`), mirroring the daemon's
  enforcement so violations surface at the emitter rather than being silently
  rejected after the write.

## [0.9.0] - 2026-05-16

### Added

- **`emitter.WithStrictErrors()` option** ([#415](https://github.com/agent-receipts/ar/pull/415)):
  When set, `Emitter.Emit()` returns errors on dial and write failures instead
  of calling `logDrop` and returning nil. Callers that do not opt in keep
  fire-and-forget semantics unchanged. Used by `agent-receipts-hook` to surface
  daemon-unreachable as a visible exit-1 failure.

## [0.8.0] - 2026-05-15

### Changed

- No SDK code changes. Version bump to maintain lockstep with the coordinated v0.8.0 release.

## [0.8.0-alpha.2] - 2026-05-10

### Changed

- No SDK code changes; version bump to maintain lockstep across the coordinated
  release (daemon process separation cutover). Releases as part of the daemon
  refactor work (ADR-0010, [#236](https://github.com/agent-receipts/ar/issues/236)).

## [0.8.0-alpha.1] - 2026-05-09

### Added

- Fire-and-forget emitter (`emitter/emitter.go`) for forwarding tool-call events
  to the `agent-receipts-daemon` Unix socket (ADR-0010, [#236](https://github.com/agent-receipts/ar/issues/236)).
  No crypto, no canonicalisation — the daemon handles those operations.

### Dependencies

- Bump `daemon` dependency to `v0.8.0-alpha.1` (initial daemon release).

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
