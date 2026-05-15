# Changelog

All notable changes to `agent-receipts-hook` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-05-16

### Changed

- **Extracted into its own Go module** ([#405](https://github.com/agent-receipts/ar/issues/405),
  [#407](https://github.com/agent-receipts/ar/pull/407)):
  `agent-receipts-hook` now lives at `github.com/agent-receipts/ar/hook` and is
  released independently of the daemon. Install path:
  `brew install agent-receipts/tap/agent-receipts-hook` or
  `go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest`.
