# Contributing to agent-receipts

Thank you for your interest in contributing to the Agent Receipts Python SDK.

## How to contribute

### Reporting issues

Open a [GitHub issue](https://github.com/agent-receipts/sdk-py/issues) for:

- Bugs in receipt creation, signing, hashing, or verification
- Store (SQLite) issues — data corruption, query problems
- Taxonomy classification errors
- Missing or incorrect type annotations
- Documentation gaps

### Proposing changes

1. Open an issue describing the change and its motivation.
2. Fork the repo and create a branch from `main`.
3. Make your changes following the conventions below.
4. Run `uv run ruff check .` and `uv run pytest -v`.
5. Open a pull request referencing the issue.

## Development setup

```sh
uv sync --all-extras
uv run pytest -v           # run all tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright src         # type check
```

## Code conventions

- **Python 3.11+** with `from __future__ import annotations`.
- **Ruff** for linting and formatting (line length 88).
- Use `TYPE_CHECKING` guards for type-only imports.
- **Pydantic v2** for receipt data models, **dataclasses** for simple types.
- Test files: `tests/` directory mirroring `src/` structure.
- All changes go through pull requests — never push directly to `main`.

## Testing

- Write tests for all new functionality and bug fixes.
- Tests use [pytest](https://docs.pytest.org/).
- Cover both happy paths and edge cases (empty inputs, invalid data, error handling).
- Use the test factories in `tests/conftest.py` for creating receipt fixtures.
- Cross-language compatibility tests in `tests/test_cross_language.py` verify parity with the TypeScript SDK.

## Spec alignment

This SDK implements the [Agent Receipt Protocol](https://github.com/agent-receipts/spec). If you find a discrepancy between the SDK behavior and the spec, please open an issue in both repos.

## Code of conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
