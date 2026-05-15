# Changelog

All notable changes to `agent-receipts-daemon` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-05-16

### Changed

- **`agent-receipts-hook` extracted into its own module** ([#405](https://github.com/agent-receipts/ar/issues/405),
  [#407](https://github.com/agent-receipts/ar/pull/407)):
  The hook binary is no longer bundled in this formula or release tarball.
  Install it separately: `brew install agent-receipts/tap/agent-receipts-hook`
  or `go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`.

## [0.8.1] - 2026-05-15

### Added

- **`agent-receipts-hook` binary** ([#403](https://github.com/agent-receipts/ar/pull/403),
  closes [#364](https://github.com/agent-receipts/ar/issues/364)):
  Short-lived PostToolUse hook for Claude Code (and future agent runtimes) that
  captures native host tool calls — `Bash`, `Write`, `Edit`, `Read`, `WebFetch`,
  `WebSearch` — and forwards them to `agent-receipts-daemon` over the Unix socket.
  Fills the audit gap left by `mcp-proxy`, which only covers MCP tool calls.
  Always exits 0 (fire-and-forget, per ADR-0010). Format-dispatch model makes
  adding new runtimes a single function + map entry.
  Shipped in the same Homebrew formula and release tarball as `agent-receipts-daemon`.

## [0.8.0] - 2026-05-15

### Added

- **Phase 2 integration tests**: concurrent mcp-proxy sessions, RFC8785-canonical
  hash verification, socket handler coverage improved from 50.9% to 81.1%
  ([#362](https://github.com/agent-receipts/ar/issues/362),
  [#365](https://github.com/agent-receipts/ar/issues/365)).
- **macOS `brew services` integration**: `brew services start agent-receipts-daemon`
  now works — `service do` block added to the Homebrew formula via GoReleaser
  template ([#375](https://github.com/agent-receipts/ar/issues/375)).
- **Binary release pipeline**: GoReleaser-backed CI workflow publishes signed
  archives and updates the Homebrew tap on each `daemon/v*` tag.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` from `v0.8.0-alpha.2` to `v0.8.0`.

## [0.8.0-alpha.2] - 2026-05-10

### Added

- **XDG-compliant default paths** ([#332](https://github.com/agent-receipts/ar/issues/332)):
  SQLite store and signing key now default to `$XDG_DATA_HOME/agent-receipts/`
  (typically `~/.local/share/agent-receipts/`) instead of `~/.agent-receipts/`.
  Consistent across Linux and macOS, follows Unix conventions, and plays well
  with standard tooling (commits `b8f9a3a`, `1f0dd21`, `081cd3e`).

- **Explicit `--init` flag for key generation** ([#348](https://github.com/agent-receipts/ar/issues/348)):
  New `agent-receipts-daemon --init` to create the signing key pair on fresh
  install. The daemon refuses to start without an existing key and never silently
  regenerates one. Prevents the footgun of accidentally replacing a deleted key
  and orphaning all previously-signed receipts (commits `1f0dd21`, `7f7231c`).

- **`--version` flag** ([#349](https://github.com/agent-receipts/ar/issues/349)):
  `agent-receipts-daemon --version` returns the build version from three sources
  in priority order: `-ldflags` injection (release pipeline), `debug.ReadBuildInfo()`
  module version (set by `go install`), or literal `"dev"` (local `go build`).
  Improves operational visibility during soaks and deployments (commit `b7589b5`).

### Security

- **TOCTOU-safe key generation** (commit `7f7231c`):
  Replaced `os.Stat` + `os.WriteFile` pattern with `O_CREATE|O_EXCL|O_NOFOLLOW + fchmod`
  to prevent symlink-based key redirection attacks during initial key write.
  Consistent with the existing `publishPublicKey` pattern.

### Tests

- 19 new tests covering XDG path defaults, environment variable overrides,
  and TOCTOU-safe key generation. Full integration suite passes including
  chain continuity across daemon restart (issue #348).

## [0.8.0-alpha.1] - 2026-05-09

### Added (ADR-0010: Daemon Process Separation)

- **New `agent-receipts-daemon` process** separates cryptographic operations
  (signing, canonicalisation, chain management) from individual SDKs/proxies
  into a dedicated daemon. SDKs emit fire-and-forget events to the daemon's
  Unix socket; the daemon produces signed, chained receipts persisted to SQLite.
  See [ADR-0010](https://github.com/agent-receipts/ar/blob/main/docs/adr/0010-daemon-process-separation.md).

- **SQLite receipt store** with persistent chain state, verification CLI
  (`agent-receipts-verify`), query support, and stats. Receipts are stored
  as canonical JSON and indexed by session/timestamp.

- **Ed25519 signing** with hierarchical key structure: one long-lived signing key
  pair per daemon instance, discoverable public key at a well-known path for
  out-of-band verification. Private keys stored with restrictive permissions (0600).

- **Unix socket IPC** for receipt events. Wire protocol: 4-byte big-endian length
  prefix + UTF-8 JSON body, matching `pipeline.SupportedFrameVersion = "1"`.

- **Session-scoped chaining** ([ADR-0010 OQ4](https://github.com/agent-receipts/ar/blob/main/docs/adr/0010-daemon-process-separation.md)):
  All receipts in a session form a cryptographic chain. Each receipt includes
  the hash of the prior receipt, enabling detection of tampering and enforcing
  causality across a session (even across daemon restarts if the key is preserved).

### Documentation

- Comprehensive suite of integration tests covering socket communication,
  chain continuity, key generation, and verification workflows.

[0.8.1]: https://github.com/agent-receipts/ar/releases/tag/daemon%2Fv0.8.1
[0.8.0]: https://github.com/agent-receipts/ar/releases/tag/daemon%2Fv0.8.0
[0.8.0-alpha.2]: https://github.com/agent-receipts/ar/releases/tag/daemon%2Fv0.8.0-alpha.2
[0.8.0-alpha.1]: https://github.com/agent-receipts/ar/releases/tag/daemon%2Fv0.8.0-alpha.1
