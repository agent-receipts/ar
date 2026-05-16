# Changelog

All notable changes to `agent-receipts-hook` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
