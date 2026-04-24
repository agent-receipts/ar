# AGENTS.md

MCP proxy that sits between an MCP client and server on stdin/stdout, intercepting every tool call to classify, score risk, evaluate policy, sign cryptographic receipts, redact sensitive data, and store an audit trail. Built with Go on [sdk/go](../sdk/go/).

## Getting started

```sh
go build ./...                         # build all
go build -o mcp-proxy ./cmd/mcp-proxy  # build binary
go test ./...                          # run tests
go vet ./...                           # static analysis
```

## Project structure

```
cmd/mcp-proxy/     # CLI entry point (serve, list, inspect, verify, export, stats, timing)
internal/
  proxy/           # STDIO proxy, JSON-RPC parsing
  audit/           # SQLite audit store, classifier, risk scorer, redaction, encryption, intent tracker
  policy/          # YAML policy engine (pass/flag/pause/block)
configs/           # Default policy rules + bundled taxonomies (embedded into the binary via go:embed)
```

## Architecture

```
MCP Client → stdin/stdout → mcp-proxy → stdin/stdout → MCP Server
                               │
                               ├── JSON-RPC parser
                               ├── Classifier + Risk scorer (0-100)
                               ├── Policy engine (YAML rules)
                               ├── Approval workflow (HTTP)
                               ├── Intent tracker (temporal grouping)
                               ├── Receipt emitter (Ed25519, hash-chained)
                               ├── Redaction (JSON-aware + pattern-based)
                               ├── Encryption at rest (AES-256-GCM)
                               └── SQLite audit store
```

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- Never break the MCP protocol — if parsing fails, forward the message raw
- Flush stdout after every proxied message
- Pure Go SQLite via modernc.org/sqlite — no CGO
- Tests sit alongside source files as `*_test.go`

## Reference files

- `internal/policy/engine.go` — policy evaluation: structured input/output, validation on init, composable matching logic
- `internal/audit/classifier.go` — operation classification and risk scoring with priority ordering
- `internal/audit/redact.go` — two-pass redaction pattern: JSON-aware key matching + regex-based secret detection

## Testing

- Run `go test ./...` to execute all tests
- Run `go test -v ./internal/audit/` (or any subpackage) to test a single area
- Tests cover: JSON-RPC parsing, classification, risk scoring, policy evaluation, redaction, encryption, receipt signing, and intent tracking
- The proxy depends on `sdk/go` via a `replace` directive — if you change `sdk/go`, re-run proxy tests too
