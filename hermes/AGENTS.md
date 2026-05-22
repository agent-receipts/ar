# AGENTS.md

hermes-agent plugin that generates cryptographically signed, hash-linked
audit trails for every tool call an agent makes, using Agent Receipts.
Receipts are W3C Verifiable Credentials signed and stored by the local
agent-receipts daemon (ADR-0010 Flavor B).

## Commands

```sh
uv sync --all-extras       # install deps
uv run pytest -v           # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright src         # type check (strict mode, must pass)
```

## Architecture

| File | Role |
|------|------|
| `src/agent_receipts_hermes/__init__.py` | Plugin entry — `register(ctx)` wires hooks + tools |
| `src/agent_receipts_hermes/hooks.py` | `pre_tool_call` / `post_tool_call` — classify + forward to daemon |
| `src/agent_receipts_hermes/classify.py` | Tool name → action type + risk level via taxonomy |
| `src/agent_receipts_hermes/daemon_store.py` | Read-only access to the daemon's SQLite database |
| `src/agent_receipts_hermes/tools.py` | Agent-facing tools: `ar_query_receipts`, `ar_verify_chain` |
| `src/agent_receipts_hermes/config.py` | Config resolution + default daemon paths |
| `src/agent_receipts_hermes/cli.py` | Receipt Explorer CLI (`agent-receipts-hermes`) |
| `src/agent_receipts_hermes/taxonomy.json` | Bundled tool → action mappings + prefix patterns |
| `src/agent_receipts_hermes/plugin.yaml` | hermes plugin manifest |

## Code conventions

- **Python ≥ 3.11**, ESM-like single package, `from __future__ import annotations` in every file
- **Strict pyright** — no `Any` leakage, `TYPE_CHECKING` guards for type-only imports
- **Frozen dataclasses** for simple immutable types
- **Ruff** for lint + format (line-length 88), import sort
- **No module-level mutable state** — all mutable state flows through `HookState` (multi-instance safe)
- **`taxonomy.json` is canonical** — tool classification comes from this file; custom taxonomies override via config

## Testing

- pytest, tests live in `tests/`
- `tests/helpers.py` exposes `FakeEmitter`, `FakeCtx`, `FakeSocketServer`
- `tests/test_integration.py` exercises `register(ctx)` end-to-end against a real `Emitter` writing to an in-process AF\_UNIX server
- New code requires colocated unit tests; integration coverage stays in `test_integration.py`

## Dependencies

- `agent-receipts` (Python SDK) — receipts, store, signing, emitter
- Pytest + pyright + ruff for dev tooling

## Security

- Never commit real private keys. Test fixtures use the SDK's
  `generate_key_pair()` (Ed25519, generated fresh per test).
- All tool-call frames are forwarded to the daemon over AF\_UNIX. Raw
  `input` and `output` JSON cross the socket so the daemon can canonicalise
  and hash them. The daemon does not persist raw values by default but
  they are observable in transit. Do not add code paths that bypass the
  daemon.
- Parameter disclosure is governed by the daemon's `--parameter-disclosure`
  flag, **not** by this plugin. Legacy openclaw-style config keys
  (`dbPath`, `keyPath`, `daemonForwarding`, `parameterDisclosure`) are
  accepted and ignored with a warning.
- Ed25519 is the only supported signing algorithm. Do not introduce
  weaker schemes.
- Validate inputs at trust boundaries (config dicts, env vars, custom
  taxonomy files). Crypto code must reject invalid inputs explicitly.

## Mindset

- Think before acting. Understand the problem before writing code.
- Work like a craftsman — do the better fix, not the quickest fix.
- Fix from first principles, not bandaids.
- Write idiomatic, simple, maintainable code.
- Delete unused code ruthlessly. No breadcrumb comments.

## Papercut rule

- Fix small issues you notice while working (typos, dead imports, minor
  inconsistencies).
- Raise larger cleanups with the user before expanding scope.

## Completing work

Before marking work as complete:

1. Confirm `uv run pytest -v && uv run pyright src && uv run ruff check .` pass.
2. Re-read your full diff — check for mistakes, consistency, and completeness.
3. Add an entry under `## [Unreleased]` in `CHANGELOG.md` for user-visible
   changes (skip for internal-only refactors or test-only edits).
4. Summarise changes with file and line references.
5. Mention any opportunistic papercut fixes made along the way.
6. Call out TODOs, follow-up work, or uncertainties.

## Agent safety rules

When working in this directory as an AI coding agent, in addition to the
conventions in `../AGENTS.md`:

- **Never modify CI/CD workflows** (`../.github/workflows/`) without
  explicit human review.
- **Never weaken cryptographic parameters** — do not change key sizes,
  hash algorithms, or signature schemes.
- **Never skip or delete existing tests** — add tests, don't remove them.
- **Never generate or commit real private keys** — use the SDK's
  `generate_key_pair()` helper inside tests only.
- **Never modify `plugin.yaml`** without explicit human approval — it
  defines the plugin's public contract with hermes.
- **Taxonomy changes** (`taxonomy.json`) must include corresponding
  test updates in `tests/test_classify.py`.
- **Always run the full test suite + linters + pyright** before
  proposing changes.
- **Use git worktrees** for new work — do not edit directly on `main`
  or shared branches.
- **Write tests first** — new functions must have test coverage before
  pushing.
