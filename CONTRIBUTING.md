# Contributing to @agent-receipts/sdk-ts

Thank you for your interest in contributing to the Agent Receipts TypeScript SDK.

## How to contribute

### Reporting issues

Open a [GitHub issue](https://github.com/agent-receipts/sdk-ts/issues) for:

- Bugs in receipt creation, signing, hashing, or verification
- Store (SQLite) issues — data corruption, query problems
- Taxonomy classification errors
- Missing or incorrect TypeScript types
- Documentation gaps

### Proposing changes

1. Open an issue describing the change and its motivation.
2. Fork the repo and create a branch from `main`.
3. Make your changes following the conventions below.
4. Run `pnpm run check` (typecheck + lint) and `pnpm run test`.
5. Open a pull request referencing the issue.

## Development setup

```sh
pnpm install
pnpm run test          # run all tests
pnpm run check         # typecheck + lint
pnpm run build         # compile to dist/
```

## Code conventions

- **TypeScript ESM** with strict mode enabled.
- Use `import type` for type-only imports (enforced by `verbatimModuleSyntax`).
- **Biome** for linting and formatting — tabs for indentation, double quotes for strings.
- Run `pnpm run lint:fix` before committing to match Biome formatting.
- Test files: `*.test.ts` colocated alongside source files in `src/`.
- All changes go through pull requests — never push directly to `main`.

## Testing

- Write tests for all new functionality and bug fixes.
- Tests use [Vitest](https://vitest.dev/).
- Cover both happy paths and edge cases (empty inputs, invalid data, error handling).
- Use the test factories in `src/test-utils/` for creating receipt fixtures.

## Spec alignment

This SDK implements the [Agent Receipt Protocol](https://github.com/agent-receipts/spec). If you find a discrepancy between the SDK behavior and the spec, please open an issue in both repos.

## Code of conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
