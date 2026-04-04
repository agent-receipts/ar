# AGENTS.md

Go SDK for the Action Receipts protocol. Provides packages for creating, signing, and verifying cryptographic receipts (Ed25519, W3C Verifiable Credentials), classifying tool calls via a taxonomy registry, and persisting receipts in SQLite.

## Getting started

```sh
go build ./...   # build all packages
go test ./...    # run all tests
go vet ./...     # static analysis
```

## Project structure

```
receipt/    # Core types, create, sign, verify, hash-chain verification
taxonomy/   # Action type registry (15 built-in types), tool call classification, config loading
store/      # SQLite receipt persistence, query, stats, chain verification
```

## Conventions

- All changes go through pull requests — never push directly to main
- Run `go vet ./...` before committing
- Keep types and logic separate where practical
- Tests sit alongside source files as `*_test.go`
- Pure Go SQLite via modernc.org/sqlite — no CGO

## Reference files

- `receipt/create.go` — pattern for receipt creation: clean input struct, single-purpose function
- `receipt/signing.go` — Ed25519 signing and verification with proper error wrapping and spec-compliant encoding

## Testing

- Run `go test ./...` to execute all tests
- Run `go test -v ./receipt/` (or any subpackage) to test a single package
- Receipt output must be byte-identical across SDKs — cross-language tests in `../../cross-sdk-tests/` verify this
