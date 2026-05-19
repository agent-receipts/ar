# Changelog

All notable changes to mcp-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.2; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [Unreleased]

### Added

- **Issuer/operator identity on receipts**: auto-detect the host that launched the proxy (Claude Code, Codex, Cursor, Windsurf) from the parent process name on Linux, and stamp `receipt.Issuer.Name`, `receipt.Issuer.Model`, and `receipt.Issuer.Operator` on every emitted receipt. Override or supplement auto-detection with `--issuer-name`, `--issuer-model`, `--operator-id`, `--operator-name` flags (or the matching `AGENTRECEIPTS_*` env vars).

## [0.9.0] - 2026-05-18

### Removed (breaking)

- **Local `audit.db` and parallel redaction/encryption layer**
  ([#453](https://github.com/agent-receipts/ar/issues/453)). Finishes the
  thin-emitter migration started in
  [#421](https://github.com/agent-receipts/ar/pull/421): the proxy no longer
  maintains its own SQLite store and no longer redacts or encrypts at rest.
  The daemon is the sole writer and the sole redactor.
  - Deleted packages: `internal/audit/{store,redact,redact_config,encrypt,intent}.go`
    and their tests (~2500 LoC).
  - Deleted CLI subcommand stubs (already deprecated in v0.8.0):
    `mcp-proxy list/inspect/verify/export/stats/timing/audit-secrets`. Use
    `agent-receipts list/verify` instead.
  - Removed flags: `-db`, `-redact-patterns`. The proxy no longer accepts
    these; passing them now exits with `flag provided but not defined`.
  - Removed env var: `BEACON_ENCRYPTION_KEY` (the proxy had no remaining
    at-rest data to encrypt once `audit.db` went away).
  - Rejected tool calls (policy `block` and approval `deny/timeout`) are
    still audited — the proxy already emits `Decision: "denied"` to the
    daemon for these, so the daemon mints receipts for them.

### Changed

- **Startup nudge for legacy `audit.db`**: if
  `$XDG_DATA_HOME/agent-receipts/audit.db` is present on serve startup, the
  proxy logs one `[INFO]` line stating the file is no longer used and is
  safe to delete. The proxy does NOT remove it — operators may want to
  archive or inspect it first. Receipts going forward live in the daemon's
  store (`agent-receipts list`).

### Migration

Operators upgrading from <0.9.0:
- Remove `-db` / `-redact-patterns` / `BEACON_ENCRYPTION_KEY` from any
  config snippets, systemd units, or wrapper scripts.
- Delete `~/.local/share/agent-receipts/audit.db` (or wherever
  `$XDG_DATA_HOME` resolved) at your leisure — the daemon's store at the
  same directory continues to be authoritative.
- If you were relying on `mcp-proxy list/inspect/verify/export/stats/timing`
  output, switch to the equivalent `agent-receipts` CLI commands shipped
  with the daemon.

## [0.8.0] - 2026-05-15

### Tests

- Improved proxy test coverage from 32.7% to 69.1% and socket handler coverage
  from 50.9% to 81.1%; fixed concurrent test timeout flakiness
  ([#376](https://github.com/agent-receipts/ar/issues/376)).

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.8.0-alpha.1` to `v0.8.0`.

## [0.8.0-alpha.1] - 2026-05-09

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.6.0` to `v0.8.0-alpha.1`.

## [0.7.0] - 2026-05-01

### Features

- **Guided `init` command** (`mcp-proxy init`) walks the operator through
  one-command setup: generates an Ed25519 signing key, writes a starter
  `config.yaml`, and prints the shell snippet to wire it into the MCP client
  config. Key files are written with restrictive permissions (0600) from the
  first write. Detailed `os.Stat` error handling and `ReadFile` error paths
  are covered by tests (commits `d463126`, `64b9f5a`, `46bcd93`, `60e7280`,
  `578ef68`).

- **Restrictive file permissions on signing keys**
  ([#156](https://github.com/agent-receipts/ar/issues/156)): `writePrivateKeyFile`
  now creates key files with mode `0600` and rejects existing files whose
  permissions are too open. `Close` errors on write failure are propagated
  rather than silently discarded (commits `3ab4912`, `0927c90`, `8148748`,
  `d323ca9`, `5a1b94e`, `b7725d8`).

- **Expanded secret redaction and `audit-secrets` scan**: the secret redaction
  pattern set is broadened to cover additional token formats; a CI
  `audit-secrets` scan is added to catch regressions (commits `de790cb`,
  `000ae5b`, `89ce066`, `e825d22`).

### Bug Fixes

- Coordinate stdio shutdown to surface upstream server death: the proxy now
  detects when the upstream MCP server exits and propagates the termination
  signal cleanly instead of hanging
  ([#158](https://github.com/agent-receipts/ar/issues/158), commit `9a0fd20`).

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.5.0` to `v0.6.0`,
  picking up `ParametersDisclosure` on `Action` and the `VerifyChain`
  hash-error surfacing fix.

### Tests

- Guard parallel-test cleanup against double `cmd.Wait` (commit `af58f46`).

[0.7.0]: https://github.com/agent-receipts/ar/compare/mcp-proxy/v0.6.2...mcp-proxy/v0.7.0

## [0.6.2] - 2026-04-29

### Changed

- Default of `-http` flag flipped from `127.0.0.1:0` to `none`; the approval
  HTTP listener is now opt-in. Pause rules still load and evaluate; an unwired
  pause fails fast with JSON-RPC code `-32003` ("no approver configured")
  instead of waiting 60s for a timeout. See
  [#266](https://github.com/agent-receipts/ar/pull/266) and
  [#262](https://github.com/agent-receipts/ar/issues/262).

- Startup banner softened. The default-off case (operator did not pass `-http`)
  now emits an `[INFO]` line with a soft "approver off by default; pass -http
  `<addr>` to enable" hint, instead of a `[WARN]`. Explicit `-http=none` is
  treated as an informed opt-out (no hint, no warn). The `[WARN]` path remains
  for the unusual misconfiguration case.

### Fixed

- Bind failure on `-http <addr>` no longer `log.Fatalf`s with a cryptic
  `bind: address already in use`. Now prints an actionable error naming the
  address and offering both `-http 127.0.0.1:0` (random port) and `-http=none`
  (disable) as remediations, then exits non-zero. Closes
  [#262](https://github.com/agent-receipts/ar/issues/262).

[0.8.0]: https://github.com/agent-receipts/ar/releases/tag/mcp-proxy%2Fv0.8.0
[0.8.0-alpha.1]: https://github.com/agent-receipts/ar/releases/tag/mcp-proxy%2Fv0.8.0-alpha.1
[0.6.2]: https://github.com/agent-receipts/ar/compare/mcp-proxy/v0.6.1...mcp-proxy/v0.6.2
