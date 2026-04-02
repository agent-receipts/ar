# sdk-go

Go SDK for the Action Receipts protocol. See [agent-receipts/spec](https://github.com/agent-receipts/spec) for the full specification.

## Toolchain

- **Language:** Go 1.22+
- **SQLite:** modernc.org/sqlite (pure Go, no CGO)
- **Testing:** `go test`

## Commands

```sh
go build ./...        # build all packages
go test ./...         # run all tests
go vet ./...          # static analysis
```

## Project structure

```
receipt/     # Core types, create, sign, verify, hash, chain verification
taxonomy/    # Action type registry, tool call classification, config loading
store/       # SQLite receipt persistence, query, stats, chain verification
```

## Conventions

- All changes go through pull requests — never push directly to main
- Use `import type` style: keep types and logic separate where practical
- Run `go vet ./...` before committing
- Tests sit alongside source files as `*_test.go`
