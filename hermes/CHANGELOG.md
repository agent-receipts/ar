# Changelog

All notable changes to `agent-receipts-hermes` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial POC of the hermes-agent Agent Receipts plugin.
- `register(ctx)` wires `pre_tool_call` / `post_tool_call` to the local
  agent-receipts daemon over AF\_UNIX (ADR-0010 Flavor B).
- Bundled taxonomy (`taxonomy.json`) covering ~50 common hermes tools
  plus prefix patterns for `browser_`, `memory_`, `subagent_`, etc.
- Agent-facing tools `ar_query_receipts` and `ar_verify_chain`,
  registered through best-effort introspection of the host `ctx`.
- Receipt Explorer CLI (`agent-receipts-hermes`) with `receipts`,
  `verify`, and `export` subcommands.
- pytest suite covering classification, config resolution, hook
  lifecycle, tools, CLI, and an end-to-end integration test against a
  real `Emitter` writing to an in-process AF\_UNIX server.
