# Changelog

All notable changes to mcp-proxy are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.6.2; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

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
