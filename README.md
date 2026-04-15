<div align="center">

# Agent Receipts

**Cryptographically signed audit trails for AI agent actions**

[![Go Tests](https://github.com/agent-receipts/ar/actions/workflows/sdk-go.yml/badge.svg)](https://github.com/agent-receipts/ar/actions/workflows/sdk-go.yml)
[![TS Tests](https://github.com/agent-receipts/ar/actions/workflows/sdk-ts.yml/badge.svg)](https://github.com/agent-receipts/ar/actions/workflows/sdk-ts.yml)
[![Python Tests](https://github.com/agent-receipts/ar/actions/workflows/sdk-py.yml/badge.svg)](https://github.com/agent-receipts/ar/actions/workflows/sdk-py.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

</div>

| | |
|---|---|
| **Project site & docs** | [agentreceipts.ai](https://agentreceipts.ai) |
| **API reference** | [Go](https://agentreceipts.ai/sdk-go/api-reference/) · [TypeScript](https://agentreceipts.ai/sdk-ts/api-reference/) · [Python](https://agentreceipts.ai/sdk-py/api-reference/) |
| **Blog** | [Your AI Agent Just Sent an Email](https://jongerius.solutions/post/your-ai-agent-just-sent-an-email/) · [Every MCP Tool Call My AI Makes Now Gets a Signed Receipt](https://jongerius.solutions/post/auditing-github-mcp-agent-receipts/) |
| **Go** | [sdk/go](https://pkg.go.dev/github.com/agent-receipts/ar/sdk/go) · [mcp-proxy](https://pkg.go.dev/github.com/agent-receipts/ar/mcp-proxy) · [dashboard](https://pkg.go.dev/github.com/agent-receipts/dashboard) |
| **npm** | [@agnt-rcpt/sdk-ts](https://www.npmjs.com/package/@agnt-rcpt/sdk-ts) |
| **PyPI** | [agent-receipts](https://pypi.org/project/agent-receipts/) |

---

## Start here

The fastest way to try Agent Receipts is to put [`mcp-proxy/`](mcp-proxy/) in front of an MCP server you already use.

In one step, you get:

- Signed receipts for every tool call
- A tamper-evident audit chain you can verify later
- Risk scoring and policy hooks without changing the client or server

If you want to audit GitHub MCP in a real agent workflow, start with:

- [Claude Desktop integration](https://agentreceipts.ai/mcp-proxy/claude-desktop/)
- [Claude Code integration](https://agentreceipts.ai/mcp-proxy/claude-code/)
- [Codex integration](https://agentreceipts.ai/mcp-proxy/codex/)

## What is this?

Agent Receipts is an open protocol and set of SDKs for producing cryptographically signed, tamper-evident records of AI agent actions. Every action an agent takes -- API calls, tool use, data access -- gets a verifiable receipt that can be audited later.

<picture>
  <img alt="How it works: Authorize → Act → Sign → Link → Audit" src=".github/how-it-works.svg">
</picture>

## Project layout

| Project | Description |
|---------|-------------|
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [`spec/`](spec/) | Protocol specification, JSON schemas, governance |
| [`sdk/go/`](sdk/go/) | Go SDK |
| [`sdk/ts/`](sdk/ts/) | TypeScript SDK |
| [`sdk/py/`](sdk/py/) | Python SDK |
| [`mcp-proxy/`](mcp-proxy/) | MCP proxy with receipt signing, policy engine, intent tracking |
| [`cross-sdk-tests/`](cross-sdk-tests/) | Cross-language verification tests |
| [dashboard](https://github.com/agent-receipts/dashboard) | Local web UI for browsing and verifying receipt databases |
| [openclaw](https://github.com/agent-receipts/openclaw) | Agent Receipts plugin for OpenClaw |

## 10-minute audited MCP quick start

Install the proxy:

```bash
go install github.com/agent-receipts/mcp-proxy/cmd/mcp-proxy@latest
```

Wrap any MCP server:

```bash
mcp-proxy node /path/to/mcp-server.js
```

Then point your agent client at the proxy instead of the raw server:

- [Claude Desktop setup](https://agentreceipts.ai/mcp-proxy/claude-desktop/)
- [Claude Code setup](https://agentreceipts.ai/mcp-proxy/claude-code/)
- [Codex setup](https://agentreceipts.ai/mcp-proxy/codex/)

Once your agent makes tool calls, inspect the signed audit trail:

```bash
mcp-proxy list
mcp-proxy inspect <receipt-id>
mcp-proxy verify --key pub.pem <chain-id>
```

## SDK quick start

### Go

```bash
go get github.com/agent-receipts/ar/sdk/go
```

```go
import receipt "github.com/agent-receipts/ar/sdk/go/receipt"

r, _ := receipt.New(receipt.WithAction("tool_call", payload))
signed, _ := r.Sign(privateKey)
```

### TypeScript

```bash
npm install @agnt-rcpt/sdk-ts
```

```typescript
import { Receipt } from "@agnt-rcpt/sdk-ts";

const receipt = await Receipt.create({ action: "tool_call", payload });
const signed = await receipt.sign(privateKey);
```

### Python

```bash
pip install agent-receipts
```

```python
from agent_receipts import Receipt

receipt = Receipt.create(action="tool_call", payload=payload)
signed = receipt.sign(private_key)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
The protocol specification in `spec/` is licensed under MIT.
