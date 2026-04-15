<div align="center">

# mcp-proxy

### MCP proxy with action receipts, policy engine, and intent tracking

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

**Audit, govern, and sign every AI agent action.**

[SDK](https://github.com/agent-receipts/ar/tree/main/sdk/go) &bull; [Spec](https://github.com/agent-receipts/spec) &bull; [agentreceipts.ai](https://agentreceipts.ai)

</div>

---

## What it does

`mcp-proxy` sits between an MCP client (Claude, etc.) and an MCP server, transparently intercepting every tool call. For each call it:

1. **Classifies** the operation (read/write/delete/execute) and scores risk (0-100)
2. **Evaluates policy** rules (pass/flag/pause/block) with approval workflows
3. **Groups** related calls by temporal proximity (intent tracking)
4. **Signs** a cryptographic receipt (Ed25519, hash-chained, W3C Verifiable Credential)
5. **Redacts** sensitive data (JSON-aware + pattern-based) before storage
6. **Stores** everything in a local SQLite audit trail

Single binary. No external dependencies. Drop-in for any MCP server.

## Install

```sh
go install github.com/agent-receipts/mcp-proxy/cmd/mcp-proxy@latest
```

## Usage

### As MCP proxy

```sh
# Wrap any MCP server
mcp-proxy node /path/to/mcp-server.js

# With options
mcp-proxy \
  --name github \
  --key private.pem \
  --taxonomy taxonomy.json \
  --rules rules.yaml \
  --issuer did:agent:my-proxy \
  --principal did:user:alice \
  node /path/to/github-mcp-server.js
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github-audited": {
      "command": "mcp-proxy",
      "args": [
        "--name", "github",
        "node", "/path/to/github-mcp-server.js"
      ]
    }
  }
}
```

### Check version

```sh
mcp-proxy -version
```

### CLI subcommands

```sh
mcp-proxy list                          # Latest 50 receipts, newest first
mcp-proxy list --risk high              # Filter by risk
mcp-proxy inspect <receipt-id>          # Show receipt details
mcp-proxy verify --key pub.pem <chain>  # Verify chain integrity
mcp-proxy export <chain-id>             # Export chain as JSON
mcp-proxy stats                         # Show statistics
mcp-proxy timing                        # Show per-tool timing breakdown
mcp-proxy timing --json                 # JSON output for dashboards
```

## Policy engine

Define rules in YAML:

```yaml
rules:
  - name: block_destructive_ops
    description: Block high-risk delete operations
    enabled: true
    tool_pattern: "delete_*"
    min_risk_score: 70
    action: block

  - name: pause_high_risk
    description: Pause for approval when risk >= 50
    enabled: true
    min_risk_score: 50
    action: pause
```

Actions: `pass` (log only), `flag` (log + highlight), `pause` (wait for approval), `block` (reject).

When a tool call is paused, approve or deny via HTTP. The approval URL and bearer token are logged to stderr at startup (the default port is random; pass `-http 127.0.0.1:PORT` to pin). Copy the token from the startup line and export it before running the curls:

```sh
export APPROVAL_TOKEN=<token-from-stderr>

curl -X POST http://127.0.0.1:PORT/api/tool-calls/{id}/approve \
  -H "Authorization: Bearer $APPROVAL_TOKEN"
curl -X POST http://127.0.0.1:PORT/api/tool-calls/{id}/deny \
  -H "Authorization: Bearer $APPROVAL_TOKEN"
```

Paused calls auto-deny after 60 seconds (fail-safe).

## Encryption

Set `BEACON_ENCRYPTION_KEY` to enable AES-256-GCM encryption at rest for sensitive audit data.

## License

Apache 2.0
