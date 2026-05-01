# Changelog

All notable changes to mcp-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.2; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

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

[0.6.2]: https://github.com/agent-receipts/ar/compare/mcp-proxy/v0.6.1...mcp-proxy/v0.6.2
