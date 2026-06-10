# Changelog

All notable changes to `agent-receipts-hermes` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (round 4)

- Relocated the plugin from `hermes/` to `plugins/hermes/` in the monorepo, and
  added a path-filtered `CI: hermes` GitHub Actions workflow (ruff + format +
  pyright + pytest across Python 3.11–3.13). Relative doc links and the
  `Homepage` URL updated for the new path.
- Documented that the plugin's tool classification (`classify.py`,
  `taxonomy.json`, the `taxonomyPath` config option) is **diagnostic only**:
  it drives log lines, not the signed receipt. The plugin forwards just the
  tool name and the daemon performs the authoritative classification. README,
  AGENTS.md, and the relevant docstrings now state this explicitly.

### Fixed (round 4)

- `_emit` now swallows transport-class failures (not only `ValueError` /
  `RuntimeError`), so the fire-and-forget guarantee holds across SDK versions:
  newer `agent-receipts` releases raise `EmitTransportError` by default
  (ADR-0025), which the pinned 0.9.0 does not. A tool call never fails because
  the audit daemon is unreachable. Covered by
  `test_emit_transport_error_does_not_propagate`.

### Internal (round 4)

- Cleared code-quality lint nits: the `EmitterLike.emit` Protocol stub carries
  a docstring instead of a bare `...`, `FakeSocketServer.stop` teardown
  `except` blocks are commented, and the thread-safety test narrows
  `BaseException` → `Exception`.

### Security (round 3)

- ``test_unserialisable_args_drop_field_not_frame`` strengthened with
  explicit "forged content not anywhere in frame" assertions, and a new
  ``test_adversarial_repr_never_reaches_wire`` integration test inspects
  the raw bytes the real ``Emitter`` writes to the socket — catching any
  regression that bypasses ``_safe_json`` directly.

### Fixed (round 3)

- ``HookState.pending`` is now guarded by a ``threading.Lock`` so
  concurrent ``pre``/``post`` invocations (e.g. parallel subagents)
  cannot trip ``_evict_stale`` mid-iteration with
  ``RuntimeError: dictionary changed size during iteration``.
- ``test_frame_layout_matches_daemon_wire_protocol`` now asserts the
  4-byte length prefix captured separately from the body, replacing the
  previous ``struct.pack(...) == struct.pack(...)`` tautology that
  survived any bug in the production code.
- ``_parse_limit`` rejects ``bool`` — without this guard ``limit=True``
  silently became ``limit=1`` because ``isinstance(True, int)`` is True.
- ``read_public_key`` distinguishes ``EACCES`` from missing-file so
  operators get a pointed hint when the daemon's key is owned by
  another user rather than a misleading "daemon not running" message.

### Changed (round 3)

- ``summarise_receipt``, ``_format_table``, ``_print_verify``,
  ``_receipt_to_jsonable``, and ``_wrap_presentation`` tightened from
  ``Any`` to ``AgentReceipt`` / ``ChainVerification`` / ``StoreStats``
  so pyright-strict catches callers passing the wrong model.
- ``_load_default_taxonomy_or_empty`` wraps the bundled-taxonomy load
  in a try/except + warning fallback to empty lists. Without this guard
  a malformed bundled ``taxonomy.json`` would raise at module import
  time and brick the entire package.

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
