# mcp-proxy

MCP proxy with action receipts, policy engine, risk scoring, and intent tracking. Built on [github.com/agent-receipts/ar/sdk/go](https://github.com/agent-receipts/ar/tree/main/sdk/go).

## Toolchain

- **Language:** Go 1.26+ (CI pins `go-version: "1.26"`; `go.mod` uses `go 1.26.1`)
- **SQLite:** modernc.org/sqlite (pure Go, no CGO)
- **Policy:** YAML rules (gopkg.in/yaml.v3)
- **Testing:** `go test`

## Commands

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
                               ├── Classifier + Risk scorer
                               ├── Policy engine (YAML rules)
                               ├── Approval workflow (HTTP)
                               ├── Intent tracker (temporal grouping)
                               ├── Receipt emitter (sign + chain via sdk-go)
                               ├── Redaction (JSON + pattern-based)
                               ├── Encryption at rest (AES-256-GCM)
                               └── SQLite audit store
```

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- The proxy must never break the MCP protocol — if parsing fails, forward raw
- Flush stdout after every proxied message
