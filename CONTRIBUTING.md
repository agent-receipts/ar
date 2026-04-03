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
