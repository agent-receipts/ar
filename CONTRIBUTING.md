# Contributing to sdk-go

Thank you for your interest in contributing to sdk-go. This document provides guidelines to make the contribution process straightforward.

## Code of Conduct

We expect all contributors to be respectful and constructive. Harassment or abusive behavior will not be tolerated.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/agent-receipts/sdk-go/issues) to report bugs or request features.
- For suspected security vulnerabilities, do not open a public issue. Instead, follow the process described in [SECURITY.md](SECURITY.md) or use [GitHub Security Advisories](https://github.com/agent-receipts/sdk-go/security/advisories/new).
- Search existing issues before creating a new one to avoid duplicates.
- Provide clear reproduction steps and environment details when reporting bugs.

### Submitting Changes

1. Fork the repository and create a feature branch from `main`.
2. Write clear, tested code that follows the existing style.
3. Run tests locally before submitting: `go test ./...`
4. Run linting: `go vet ./...`
5. Open a pull request against `main`.

### Pull Request Guidelines

- Keep PRs focused on a single change.
- Write a clear title and description explaining the motivation for the change.
- Ensure all tests pass and add new tests for new functionality.
- Be responsive to review feedback.

## Development Setup

```bash
git clone https://github.com/agent-receipts/sdk-go.git
cd sdk-go
go mod download
go test ./...
```

## Licensing

This project is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your contributions will be licensed under the same license. All new files should include the appropriate license header where applicable.

## Questions

If you have questions about contributing, feel free to open an issue for discussion.
