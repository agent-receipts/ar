# AGENTS.md

Monorepo for the Agent Receipts protocol — cryptographically signed audit trails for AI agent actions. Contains the protocol spec, SDKs in three languages, an MCP proxy, and the documentation site.

## Monorepo layout

```
spec/          # Protocol specification and JSON schemas
sdk/go/        # Go SDK (receipt, store, taxonomy)
sdk/ts/        # TypeScript SDK (@agent-receipts/sdk-ts)
sdk/py/        # Python SDK (agent-receipts)
mcp-proxy/     # MCP STDIO proxy with audit, policy, and receipts (Go)
site/          # Documentation site (Astro)
cross-sdk-tests/  # Cross-language receipt verification tests
```

Each subdirectory has its own AGENTS.md with project-specific details.

## Quick reference

| Component | Language | Test command | Build command |
|-----------|----------|-------------|---------------|
| sdk/go | Go | `go test ./...` | `go build ./...` |
| sdk/ts | TypeScript | `pnpm test` | `pnpm build` |
| sdk/py | Python | `uv run pytest` | `uv build` |
| mcp-proxy | Go | `go test ./...` | `go build ./cmd/mcp-proxy` |
| site | TypeScript | — | `pnpm build` |
| spec | — | — | JSON schema validation |

## Conventions

- All changes go through pull requests — never push directly to main
- CI is path-filtered: changes to `sdk/go/` only trigger Go SDK CI
- mcp-proxy CI also triggers on `sdk/go/` changes (dependency)
- Site deploys on `site/**` or `spec/**` changes
- Go modules use a `replace` directive for local development (mcp-proxy → sdk/go)
- Run language-specific linters before committing (go vet, biome, ruff)

## Dependencies

```
spec (protocol definition)
  ↓
sdk/go ← mcp-proxy (Go replace directive for local dev)
sdk/ts
sdk/py
```

SDKs are independent implementations of the same spec. They do not depend on each other but must produce compatible receipts (same canonical JSON, same signature encoding, same hash format).

## Security

- Never commit real private keys. Test fixtures use well-known test keys only (see each SDK's test helpers).
- Never store plaintext secrets in receipts — parameters must be hashed before inclusion.
- Ed25519 is the only supported signing algorithm. Do not introduce alternative or weaker schemes.
- Report vulnerabilities via [GitHub Security Advisories](https://github.com/agent-receipts/ar/security/advisories/new), not public issues. See [SECURITY.md](SECURITY.md).

## Mindset

- Think before acting. Understand the problem before writing code.
- Work like a craftsman — do the better fix, not the quickest fix.
- Fix from first principles, not bandaids.
- Write idiomatic, simple, maintainable code.
- Delete unused code ruthlessly. No breadcrumb comments ("moved to X", "removed").
- Leave the repo better than you found it.

## Papercut rule

- Fix small issues you notice while working (typos, dead imports, minor inconsistencies).
- Raise larger cleanups with the user before expanding scope.

## Timeout handling

- If a command runs longer than 35 minutes, stop it, capture logs/context, and check with the user.
- Do not wait indefinitely for hung processes.

## Agent safety rules

When working in this repo as an AI coding agent, these rules apply in addition to the conventions above:

- **Never modify CI/CD workflows** (`.github/workflows/`) without explicit human review
- **Never weaken cryptographic parameters** — do not change key sizes, hash algorithms, or signature schemes
- **Never skip or delete existing tests** — add tests, don't remove them
- **Never generate real cryptographic keys** — always use test fixtures from each SDK's test helpers
- **Never modify the protocol spec** (`spec/`) without explicit human approval
- **Always run the full test suite** for any SDK you change before proposing a PR
- **Cross-SDK changes require cross-language test verification** — if you change receipt format in one SDK, verify the cross-language tests still pass
- **Use git worktrees** for new work — do not edit directly on main or shared branches, to avoid conflicts with other agents or in-progress work
- **Self-review before committing** — read back your full diff before committing or opening a PR. Check for mistakes, consistency, and completeness
