# AGENTS.md

Short-lived PostToolUse hook binary for agent runtimes (Claude Code, Codex, …). Reads a JSON frame from stdin, maps it to an `emitter.Event`, and forwards it to `agent-receipts-daemon` over a Unix-domain socket. Always exits 0 — never blocks the agent. Built on [sdk/go/emitter](../sdk/go/emitter/).

## Getting started

```sh
go build ./cmd/agent-receipts-hook  # build binary
go test ./...                       # run tests (includes integration tests on linux/darwin)
go vet ./...                        # static analysis
```

## Project structure

```
cmd/agent-receipts-hook/
  main.go              # stdin read, format detection, emitter dispatch
  claude_code.go       # Claude Code PostToolUse frame parser
  main_test.go         # unit tests for readClaudeCode and detect
  integration_test.go  # end-to-end tests against a real AF_UNIX listener (linux/darwin)
```

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- The binary must always exit 0 — silent failure is the contract (ADR-0010 §"Failure model")
- No CGO — pure Go only
- Adding a new runtime format: add a `reader` func and register it in `formats` map in `main.go`

## Dependencies

`hook/go.mod` requires only `sdk/go`. `daemon` appears as `// indirect` because `sdk/go`'s
`emitter_test.go` imports it under the `integration && (linux || darwin)` build tag and
Go 1.26's tidy follows that edge. Lazy loading (go 1.17+) ensures daemon is never downloaded
when building or installing the hook binary.

## Testing

- `go test ./...` runs unit tests and integration tests (linux/darwin build tag is satisfied in CI and locally)
- Integration tests spin up an in-process `recordingListener` on a real AF_UNIX socket — no daemon process required
- `TestIntegration_DaemonDown` verifies the fire-and-forget contract: Emit completes in <250ms when the socket is unreachable

## Release

Tagged `hook/vX.Y.Z` — triggers `.github/workflows/release-hook.yml`, which runs GoReleaser
from the `hook/` directory and publishes `agent-receipts-hook` to the Homebrew tap.
The `release-hook` GitHub environment must exist before the first release.
