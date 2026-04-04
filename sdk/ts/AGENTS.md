# AGENTS.md

TypeScript SDK for the Agent Receipts protocol — create, sign, hash-chain, store, and verify cryptographically signed audit trails for AI agent actions. Zero runtime dependencies (Node.js built-ins only).

## Commands

```sh
pnpm install        # install deps
pnpm build          # compile (tsc → dist/)
pnpm test           # vitest
pnpm typecheck      # tsc --noEmit
pnpm lint           # biome check
pnpm lint:fix       # biome check --write
```

## Project structure

```
src/
  receipt/
    types.ts       # W3C Verifiable Credential types and interfaces
    create.ts      # Receipt creation with auto-generated IDs
    signing.ts     # Ed25519 signing and verification
    hash.ts        # RFC 8785 canonicalization + SHA-256
    chain.ts       # Hash chain verification
  store/
    store.ts       # SQLite persistence (node:sqlite)
    verify.ts      # Chain verification against stored receipts
  taxonomy/
    actions.ts     # Action type definitions (15 built-in types)
    classify.ts    # Tool call classification
    config.ts      # Taxonomy config loading
  test-utils/      # Shared test helpers
  index.ts         # Public API exports
```

## Conventions

- **ESM-only** (`"type": "module"`, imports use `.js` extensions)
- **Strict TypeScript** — `strict: true`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`
- **Zero runtime dependencies** — only `node:crypto` and `node:sqlite`
- **Colocated tests** — `foo.ts` → `foo.test.ts` in the same directory
- **Biome** for linting and formatting (tab indentation, double quotes)
- **Explicit type imports** — use `import type` for type-only imports
- **No default exports** — use named exports throughout
- Output must be byte-identical to the Go and Python SDKs

## Reference files

- `src/receipt/create.ts` — receipt creation pattern: typed input, single-purpose function, JSDoc documentation
- `src/receipt/hash.ts` — RFC 8785 canonicalization with comprehensive edge case handling
- `src/receipt/hash.test.ts` — test structure: helper factories, edge case coverage, clear describe/it blocks

## Testing

- Vitest with colocated `.test.ts` files
- Helper factories in `src/test-utils/` for receipt and stream test data
- Receipt output must be byte-identical across SDKs — cross-language tests in `../../cross-sdk-tests/` verify this
