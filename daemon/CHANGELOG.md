# Changelog

All notable changes to `agent-receipts-daemon` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.0] - 2026-06-02

### Added

- **`agent-receipts verify-event`** ([#659](https://github.com/agent-receipts/ar/pull/659), closes [#540](https://github.com/agent-receipts/ar/issues/540)) — read-only CLI subcommand for end-to-end pipeline-provenance evidence. Where `verify` answers "is this chain internally consistent?", `verify-event` answers "was this receipt produced by the documented emitter→daemon→chain pipeline, or written to the store by some other path?" (ADR-0010 § Permissions and trust). Resolves receipts by `--id`, `--chain-head`, or `--since` window and runs six checks per receipt: signature, hash linkage, peer-credential presence, emitter-identity allowlist (warns, never fails), schema-version compatibility, and sequence contiguity. Exit `0` verified + provenance confirmed / `1` check failed / `2` usage error / `3` verifies cryptographically but lacks peer-credential evidence. `--json` for CI. Safe to run against a live daemon's DB or a forensic snapshot — never emits.
- **TOML config file support** ([#441](https://github.com/agent-receipts/ar/issues/441)) — the daemon now reads a TOML config file, by default `$XDG_DATA_HOME/agent-receipts/daemon.toml` (falling back to `~/.local/share/agent-receipts/daemon.toml`), co-located with `receipts.db` and the signing key. Override the path with `--config` or `AGENTRECEIPTS_CONFIG`. Keys mirror the flag names (dashes → underscores): `socket`, `db`, `key`, `public_key`, `chain_id`, `issuer_id`, `verification_method`, `parameter_disclosure`, `redact_patterns`, `unsafe_socket_path`, `shutdown_deadline`. Precedence is **file < env < flags** — the file is the lowest-priority layer, so an absent key never clobbers an env var or flag. A missing default-path file is tolerated; a missing `--config` path, malformed TOML, or an unknown key is rejected rather than silently degrading. New `--print-config` prints the fully resolved config (paths only — never key material) in the same shape, so it doubles as a starting `daemon.toml`.
- **`agent-receipts doctor`** ([#539](https://github.com/agent-receipts/ar/issues/539)) — read CLI subcommand that diagnoses the whole pipeline (emitter → socket → daemon → SQLite → verify) end-to-end and reports an actionable per-step result. Eight checks: daemon reachability, socket presence/mode, emitter-vs-daemon dial-path agreement, DB permissions (`0640` per ADR-0010 § Read interface), schema readability + public-key fingerprint, OS peer-credential capability, chain-head verification (surfacing the verifier's `unknown` status as a warning per [#475](https://github.com/agent-receipts/ar/issues/475)), and a load-bearing **round-trip**: a synthetic event fired through the real socket must land in the DB with a fresh peer credential matching the doctor process. `--json` for CI, `--warn-as-error` for stricter gates, `--no-roundtrip` to skip writing a synthetic event. Exit `0` healthy / `1` unhealthy / `2` usage. The synthetic event is deliberately visible in the chain (channel `doctor`, tool `agent-receipts-doctor.roundtrip`, recorded as `action.type` `doctor.agent-receipts-doctor.roundtrip` — a low-risk diagnostic self-check operators can filter on).

### Changed

- **Boolean environment variables now parse via `strconv.ParseBool`** ([#441](https://github.com/agent-receipts/ar/issues/441)) — `AGENTRECEIPTS_PARAMETER_DISCLOSURE` and the new `AGENTRECEIPTS_UNSAFE_SOCKET_PATH` previously treated only the literal `1` as true and silently ignored everything else. They now accept the full `strconv.ParseBool` set (`1`/`0`, `t`/`f`, `true`/`false`, `TRUE`/`FALSE`, …) and **reject** unparseable garbage with a startup error instead of degrading to false. Operators upgrading should know: values like `true`/`false` now take effect as expected, a previously-ignored non-`1` truthy value (e.g. `yes`) will now error rather than silently being treated as false, and `AGENTRECEIPTS_PARAMETER_DISCLOSURE=true` is now honoured.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.14.0`.

## [0.13.0] - 2026-05-24

### Added

- **`agent-receipts show <seq>`** ([#576](https://github.com/agent-receipts/ar/pull/576), closes [#552](https://github.com/agent-receipts/ar/issues/552)) — read-only CLI subcommand that prints the full fields of the receipt at a given chain sequence number. `--json` for raw receipt output. `--chain-id` required only when the store holds more than one chain; single chains are auto-detected.
- **`chain.status="interrupted"` terminal receipt on SIGTERM/SIGINT** ([#582](https://github.com/agent-receipts/ar/pull/582), closes [#500](https://github.com/agent-receipts/ar/issues/500)) — after the IPC listener closes and all in-flight frames drain, the daemon now emits a terminal receipt (`chain.terminal=true`, `chain.status="interrupted"`) for every open chain before exiting. Verifiers classify the chain as `"interrupted"` rather than `"unknown"`. Uses `GetChainTailReceipt` to avoid emitting a duplicate if the chain already has a terminal.
- **`action.idempotency_key` auto-populated from JSON-RPC request id** ([#565](https://github.com/agent-receipts/ar/pull/565)) — the daemon now stamps `idempotency_key` from the `id` field of the wrapped JSON-RPC request (capped at 256 bytes). Requires sdk/go v0.13.0 and spec v0.4.0.
- **Refuse unsafe socket paths absent `--unsafe-socket-path`** ([#579](https://github.com/agent-receipts/ar/pull/579), closes [#538](https://github.com/agent-receipts/ar/issues/538)) — at startup the daemon rejects a `--socket` / `AGENTRECEIPTS_SOCKET` override that resolves outside the per-platform safe set (Linux: `$XDG_RUNTIME_DIR`, `/run`, `/var/run`; macOS: `$TMPDIR`, `/var/run`, `$XDG_DATA_HOME/agent-receipts`) unless `--unsafe-socket-path` is also passed. With the flag the daemon starts, logs a `level=warn` line naming the path, and re-emits the warning every 60s. Paths are canonicalized with `filepath.EvalSymlinks`; TCP addresses are rejected unconditionally.

### Changed

- **macOS default socket path moved off `$TMPDIR`** ([#545](https://github.com/agent-receipts/ar/issues/545)) — the macOS default is now `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`). The previous TMPDIR-based path was not inherited by GUI-spawned subprocesses (e.g., MCP servers launched by Claude Desktop), causing silent receipt-loss mismatches. Linux defaults are unchanged. Operators upgrading on macOS must restart both the daemon and any emitter; anyone relying on TMPDIR redirection should switch to `AGENTRECEIPTS_SOCKET`.
- **`daemon.DefaultSocketPath` now delegates to `emitter.DefaultSocketPath`** — eliminates the duplicate resolver that could drift. Library consumers of `daemon.DefaultSocketPath` now also pick up `AGENTRECEIPTS_SOCKET` directly.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.13.0`.

## [0.12.1] - 2026-05-23

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.12.1` (HttpEmitter + Emitter interface, macOS socket path default — no daemon behaviour change).

## [0.12.0] - 2026-05-22

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.11.0` (v0.3.0 spec migration: HPKE disclosure envelope, PeerCredential, EmitterMetadata — no daemon behaviour change beyond what was already shipped in v0.11.0).

## [0.11.0] - 2026-05-19

### Added

- **Issuer/operator metadata in receipts**: the daemon now stamps `receipt.Issuer.Name`, `receipt.Issuer.Model`, and `receipt.Issuer.Operator` from the proxy-supplied wire fields (`issuer_name`, `issuer_model`, `operator_id`, `operator_name`). Old proxies that omit these fields produce receipts with empty Name/Operator, preserving backwards compatibility.

### Fixed

- **MCP tool-level failures now record `outcome.status: "failure"`**:
  When an MCP tool call returned a `CallToolResult` envelope with
  `"isError": true`, the JSON-RPC call still succeeded (no `Error` on the
  emitter frame), so the daemon stamped the receipt with
  `outcome.status: "success"`. The pipeline now inspects the result body for
  the MCP `isError` flag on `channel == "mcp"` frames and maps it to
  `failure`. Other channels are unaffected — a top-level `isError` outside
  the MCP envelope is not reinterpreted.

## [0.10.1] - 2026-05-18

### Security

- **Redact bare JWT tokens in receipts** ([#451](https://github.com/agent-receipts/ar/pull/451),
  closes [#450](https://github.com/agent-receipts/ar/issues/450)):
  The pipeline redactor missed JWTs that were not prefixed with `Bearer ` and
  not embedded in a URL query string. Concretely, `cat ~/.npmrc` from a Claude
  Code `Bash` tool call produced a receipt with the npm `_authToken=eyJ…` value
  in cleartext. Added a `jwt` built-in pattern (`eyJ…\.eyJ…\.…`) anchored on
  the base64url-encoded `{"` prefix of the header and payload segments, which
  keeps the pattern specific to real JWTs and avoids matching arbitrary dotted
  base64 strings. The signature segment may be empty (covers unsigned
  `alg=none` tokens).

## [0.10.0] - 2026-05-17

### Added

- **Receipt pipeline redaction** ([#426](https://github.com/agent-receipts/ar/pull/426),
  closes [#423](https://github.com/agent-receipts/ar/issues/423)):
  The daemon now redacts secrets from receipt body fields before persistence.
  Built-in patterns cover GitHub PATs, OpenAI/Anthropic keys, AWS access key IDs,
  bearer tokens, Slack tokens, PEM private keys, and URL query-string tokens.
  JSON-aware key redaction additionally covers `password`, `token`, `api_key`,
  `secret`, `authorization`, `private_key`, `jwt`, and 20+ other sensitive key names.
  Redaction runs after hashing — `parameters_hash` and `response_hash` commit to
  the raw canonical bytes; only the stored text fields (`outcome.error`,
  `parameters_disclosure` when enabled) are sanitised.
  Custom patterns can be added via `--redact-patterns <file.yaml>`
  (env: `AGENTRECEIPTS_REDACT_PATTERNS`).

- **`agent-receipts list` companion CLI command** ([#420](https://github.com/agent-receipts/ar/pull/420),
  closes [#410](https://github.com/agent-receipts/ar/issues/410)):
  `agent-receipts list` prints recent receipts from the daemon store in tabular
  or JSON form. Flags: `--limit N` (default 50), `--json`, `--db`/`AGENTRECEIPTS_DB`.
  Newest-first by default.

### Changed

- **mcp-proxy is now a thin emitter** ([#421](https://github.com/agent-receipts/ar/pull/421),
  closes [#416](https://github.com/agent-receipts/ar/issues/416)):
  The mcp-proxy no longer maintains its own `receipts.db` or signs receipts.
  It forwards raw tool-call events to the daemon over the Unix socket
  (the same pattern as `agent-receipts-hook`). The daemon is the sole receipt
  writer. **Breaking change for mcp-proxy:** the `-receipt-db`, `-key`, `-chain`,
  `-issuer*`, `-operator*`, `-principal`, `-taxonomy`, and `-bundled-taxonomies`
  flags have been removed. The `mcp-proxy list`, `inspect`, `verify`, `export`,
  and `stats` subcommands now print a deprecation notice pointing to
  `agent-receipts list` / `agent-receipts verify`.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.9.1`
  (DESC ordering and no silent 10k row cap in `QueryReceipts`).

## [0.9.1] - 2026-05-16

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.9.0`
  (`emitter.WithStrictErrors()` option added; no daemon behaviour change).

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
