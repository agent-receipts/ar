# Contributing to Agent Receipts

## Monorepo structure

```
spec/          Protocol specification (MIT licensed)
sdk/go/        Go SDK
sdk/ts/        TypeScript SDK
sdk/py/        Python SDK
mcp-proxy/     MCP proxy with receipt signing, policy engine, and intent tracking
cross-sdk-tests/  Cross-language receipt verification tests
```

## Running tests

**Go**
```bash
cd sdk/go && go test ./...
```

**TypeScript**
```bash
cd sdk/ts && npm install && npm test
```

**Python**
```bash
cd sdk/py && uv sync && uv run pytest
```

**MCP Proxy (Go)**
```bash
cd mcp-proxy && go test ./...
```

## Pre-commit hooks

This repo uses [Lefthook](https://github.com/evilmartians/lefthook) for pre-commit and pre-push hooks across all languages.

```bash
brew install lefthook   # or: go install github.com/evilmartians/lefthook@latest
lefthook install        # set up git hooks
```

**Pre-commit** (fast, triggered by staged changes): `go vet`, `gofmt`, `biome check`, `ruff check`, `ruff format --check`

**Pre-push** (heavier): `go test`, `tsc --noEmit`, `vitest run`, `pytest`

Hooks run in parallel and are scoped per subdirectory — staged changes determine which subdirectories run, and only the languages you changed get checked.

## Working with AI agents

AI agents (Claude Code, Copilot, etc.) are first-class contributors to this project. See [AGENTS.md](AGENTS.md) for the full agent safety rules and conventions.

**Test-driven workflow** — the highest-leverage pattern for agent-assisted development:

1. Write a failing test that describes the expected behavior.
2. Let the agent implement the fix or feature to make the test pass.
3. The test output gives the agent a tight feedback loop — it can iterate without guessing.

**Cross-language verification** — when changing receipt format, signing, or hashing:

1. Run `cross-sdk-tests/` before starting to establish a baseline.
2. Make changes in one SDK.
3. Run cross-language tests again to catch compatibility issues before they spread.

**Agent boundaries** — agents must follow the [Agent safety rules](AGENTS.md#agent-safety-rules). Key constraints: no spec changes without human approval, no CI workflow changes, no real cryptographic keys.

## Pull request guidelines

- CI is path-filtered: only the workflows relevant to the directories you changed will run.
- A single PR can touch multiple SDKs or the spec -- this is encouraged when a spec change needs SDK updates.
- Keep commits atomic: separate spec changes from SDK implementation where practical.
- All PRs require passing CI before merge.

## Good first contributions

- **Add action types** to the taxonomy (`spec/taxonomy/action-types.json`) — follow the `domain.resource.verb` pattern
- **Improve documentation** on the [site](site/) — fix typos, add examples, clarify explanations
- **Add test cases** — especially cross-language test vectors in `cross-sdk-tests/`
- **Improve error messages** in any SDK — clearer messages help everyone debug faster

## Pre-submit checklist

Before opening a PR, verify:

- [ ] Tests pass for every component you changed (see [Running tests](#running-tests))
- [ ] Linter passes (`go vet`, `ruff check`, `biome` as applicable)
- [ ] No real keys or secrets in the diff — use test fixtures only
- [ ] Cross-language tests pass if you changed receipt creation, signing, or hashing
- [ ] AGENTS.md updated if you changed project structure

## Protocol questions

See the [spec](spec/) directory for the protocol specification, schema definitions, and governance docs.
