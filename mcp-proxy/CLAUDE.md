# mcp-proxy

Thin MCP proxy: enforces policy on tool calls and forwards completed events to the [agent-receipts daemon](https://github.com/agent-receipts/ar/tree/main/daemon) for signing and persistence. The daemon is the sole writer; the proxy holds no SQLite store of its own (since v0.9.0 — see ADR-0010, [#421](https://github.com/agent-receipts/ar/pull/421), [#453](https://github.com/agent-receipts/ar/issues/453)).

## Toolchain

- **Language:** Go 1.26+ (CI pins `go-version: "1.26"`; `go.mod` uses `go 1.26.1`)
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
cmd/mcp-proxy/     # CLI entry point (serve, doctor, init)
internal/
  proxy/           # STDIO proxy, JSON-RPC parsing
  audit/           # Classifier, risk scorer, approval manager (no persistence)
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
                               ├── Approval workflow (HTTP, in-memory)
                               └── Daemon emitter (forwards completed events
                                   to agent-receipts-daemon over AF_UNIX;
                                   daemon owns redaction, hashing, signing,
                                   chaining, and persistence)
```

## Conventions

- All changes go through pull requests
- Run `go vet ./...` before committing
- The proxy must never break the MCP protocol — if parsing fails, forward raw
- Flush stdout after every proxied message
- Redaction and persistence are daemon responsibilities — do not reintroduce a local store
