# Changelog

## Unreleased

### Changed

- Extracted `agent-receipts-hook` from the `daemon` module into its own Go module (`github.com/agent-receipts/ar/hook`). The `go install` path is now `github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`. Homebrew install path changes to `brew install agent-receipts/tap/agent-receipts-hook`.
