# Changelog

All notable changes to `agent-receipts-hook` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0] - 2026-06-11

Graduates `0.15.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.17.0` (the alpha pinned `v0.17.0-alpha.1`). See the `0.15.0-alpha.1` entry below for the full surface (`agent_type` forwarding).

## [0.15.0-alpha.1] - 2026-06-09

### Added

- **`agent_type` forwarding** ([#761](https://github.com/agent-receipts/ar/pull/761), ADR-0026) — the Claude Code hook now parses `agent_type` from the PostToolUse payload and forwards it to the emitter alongside the existing `agent_id`. The daemon nests both under `issuer.runtime`.

### Changed

- Pin `github.com/agent-receipts/ar/sdk/go` to `v0.17.0-alpha.1` (carries the `agent_type` emitter field).

## [0.14.0] - 2026-06-09

Graduates `0.14.0-alpha.1` after the alpha pass. No code changes since the alpha; the only change is pinning the now-released stable `github.com/agent-receipts/ar/sdk/go` `v0.16.0` (the alpha pinned `v0.16.0-alpha.1`). See the `0.14.0-alpha.1` entry below for the full surface (`agent_id` and `correlation_id` forwarding).

## [0.14.0-alpha.1] - 2026-06-08

### Added

- **`agent_id` forwarding** ([#753](https://github.com/agent-receipts/ar/pull/753)) — Claude Code sends a distinct `agent_id` per subagent in hook payloads. The hook now parses this field from the `claudeCodeFrame` and sets it on `emitter.Event.AgentID`, enabling the daemon to route subagent frames to per-agent chains and attach delegation backlinks.
- **`correlation_id` forwarding** ([#752](https://github.com/agent-receipts/ar/pull/752)) — the hook now reads `tool_use_id` from the Claude Code payload and forwards it as `Event.CorrelationID`. This links every pre-check receipt to the corresponding post-action receipt emitted by the MCP proxy for the same tool invocation.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.16.0-alpha.1`.

## [0.13.0] - 2026-06-01

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.14.0` (response hash, redaction patterns, HPKE forensic key helpers, action-type forwarding).

## [0.12.0] - 2026-05-24

### Changed

- **macOS default socket path moved off `$TMPDIR`** ([#545](https://github.com/agent-receipts/ar/issues/545)) — inherited from the SDK's updated `emitter.DefaultSocketPath`: the hook now resolves to `$XDG_DATA_HOME/agent-receipts/events.sock` (defaulting to `~/.local/share/agent-receipts/events.sock`) instead of `$TMPDIR/agentreceipts/events.sock`. Avoids the silent path mismatch when the hook is spawned by a process that does not propagate TMPDIR (e.g., a GUI host). Operators on macOS should restart the daemon so both sides resolve to the same path.

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.13.0` (PeerCredential `*uint32`, WalEmitter, AWS KMS adapter, `store.Exists`, safe socket path enforcement, idempotency_key).

## [0.11.1] - 2026-05-23

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.12.1` (HttpEmitter + Emitter interface, macOS socket path default).

## [0.11.0] - 2026-05-22

### Dependencies

- Bump `github.com/agent-receipts/ar/sdk/go` to `v0.11.0` (v0.3.0 spec migration: HPKE disclosure envelope, PeerCredential, EmitterMetadata — no hook behaviour change).

## [0.10.0] - 2026-05-16

### Added

- **PreToolUse support** ([#415](https://github.com/agent-receipts/ar/pull/415)):
  The hook now handles `hook_event_name: "PreToolUse"` payloads in addition to
  `"PostToolUse"`. PreToolUse frames emit a receipt with `decision: "pending"`;
  PostToolUse frames continue to emit `decision: "allowed"`. Configure both in
  `~/.claude/settings.json` to capture full intent + outcome pairs, or use
  either event in isolation.

### Fixed

- **Claude Code runtime detection** ([#411](https://github.com/agent-receipts/ar/pull/411)):
  Claude Code does not set `CLAUDE_SESSION_ID` as an environment variable —
  it passes `hook_event_name` in the stdin JSON payload instead. The previous
  detection check looked only at the env var, so every invocation was silently
  dropped as an unknown runtime. Detection now checks the payload for
  `hook_event_name: "PostToolUse"` or `"PreToolUse"` and falls back to the
  env var for forward compatibility.

### Changed

- **Fail hard once runtime is identified** ([#415](https://github.com/agent-receipts/ar/pull/415)):
  All error paths after format detection now exit 1 with a message to stderr
  instead of silent exit 0. Affected cases: unsupported format string,
  unparseable payload (schema change), `emitter.New()` failure, and
  `Emit()` failure (daemon unreachable, using `WithStrictErrors()`). The only
  remaining silent exit 0 path is unrecognised runtime — not our concern.

## [0.9.0] - 2026-05-16

### Changed

- **Extracted into its own Go module** ([#405](https://github.com/agent-receipts/ar/issues/405),
  [#407](https://github.com/agent-receipts/ar/pull/407)):
  `agent-receipts-hook` now lives at `github.com/agent-receipts/ar/hook` and is
  released independently of the daemon. Install path:
  `brew install agent-receipts/tap/agent-receipts-hook` or
  `go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`.
