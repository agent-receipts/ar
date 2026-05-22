# Changelog

All notable changes to `agent-receipts-hermes` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `_safe_json` no longer falls back to ``repr()`` for unknown objects —
  an attacker-controllable ``__repr__`` could otherwise inject misleading
  content into the signed audit trail. Non-serialisable values now cause
  the affected field to be dropped (the frame itself still goes through).

### Fixed

- Removed dead post-filter in ``query_receipts`` that re-applied
  ``timestamp != after`` after the SDK had already filtered with
  ``timestamp > ?`` (strictly exclusive). The accompanying comment
  inverted the SDK's actual semantics.
- ``tests/test_integration.py`` no longer asserts a tautology when
  checking the wire-format length prefix.

### Changed

- ``__all__`` trimmed to ``["VERSION", "register"]``; all other symbols
  remain importable from their submodules for tests and advanced use.
- ``_attempt_register_tool`` narrows its swallowed exceptions to
  ``TypeError | AttributeError`` and logs each rejected candidate at
  DEBUG so operators can diagnose mismatches against undocumented
  hermes APIs.
- ``plugin.yaml`` no longer declares the ``tools:`` block — tool
  registration is via ``ctx`` at runtime, matching the langfuse
  reference plugin and avoiding double-registration ambiguity.
- ``summarise_receipt`` and ``broken_at_or_none`` lifted into
  ``daemon_store`` and shared between the agent tools and the CLI.

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
