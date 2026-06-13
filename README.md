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
| **Daemon setup & migration guide** | [agentreceipts.ai/getting-started/daemon-setup/](https://agentreceipts.ai/getting-started/daemon-setup/) |
| **API reference** | [Go](https://agentreceipts.ai/sdk-go/api-reference/) · [TypeScript](https://agentreceipts.ai/sdk-ts/api-reference/) · [Python](https://agentreceipts.ai/sdk-py/api-reference/) |
| **Blog** | [Your AI Agent Just Sent an Email](https://jongerius.solutions/post/your-ai-agent-just-sent-an-email/) · [Every MCP Tool Call My AI Makes Now Gets a Signed Receipt](https://jongerius.solutions/post/auditing-github-mcp-agent-receipts/) |
| **Go** | [sdk/go](https://pkg.go.dev/github.com/agent-receipts/ar/sdk/go) · [mcp-proxy](https://pkg.go.dev/github.com/agent-receipts/ar/mcp-proxy) · [dashboard](https://pkg.go.dev/github.com/agent-receipts/dashboard) |
| **npm** | [@obsigna/sdk-ts](https://www.npmjs.com/package/@obsigna/sdk-ts) |
| **PyPI** | [obsigna](https://pypi.org/project/obsigna/) |

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
| [`daemon/`](daemon/) | Signing daemon — out-of-process key custody, shared audit chain |
| [`mcp-proxy/`](mcp-proxy/) | MCP proxy with receipt signing, policy engine, intent tracking |
| [`cross-sdk-tests/`](cross-sdk-tests/) | Cross-language verification tests |
| [dashboard](https://github.com/agent-receipts/dashboard) | Local web UI for browsing and verifying receipt databases |
| [openclaw](https://github.com/agent-receipts/openclaw) | Agent Receipts plugin for OpenClaw |

## 10-minute audited MCP quick start

Install the proxy:

```bash
go install github.com/agent-receipts/ar/mcp-proxy/cmd/obsigna-mcp@latest
```

Wrap any MCP server:

```bash
obsigna-mcp node /path/to/mcp-server.js
```

Then point your agent client at the proxy instead of the raw server:

- [Claude Desktop setup](https://agentreceipts.ai/mcp-proxy/claude-desktop/)
- [Claude Code setup](https://agentreceipts.ai/mcp-proxy/claude-code/)
- [Codex setup](https://agentreceipts.ai/mcp-proxy/codex/)

Once your agent makes tool calls, inspect the signed audit trail:

```bash
obsigna list
obsigna show <seq>
obsigna verify
```

## SDK quick start

> **Choose your trust model.** The snippets below keep the signing key inside the
> agent process — a deliberate deployment model where the agent host is trusted
> and tamper-evidence is aimed at downstream parties. In this model, anyone with
> code execution in the agent can forge receipts. To defend against a compromised
> agent, use the
> [daemon-mediated path](https://agentreceipts.ai/getting-started/daemon-setup/),
> where a separate daemon owns the key and your app only sends events over a
> socket. See the [Trust Model](https://agentreceipts.ai/specification/trust-model/)
> page for the full spectrum (in-process → daemon-isolated → HSM/KMS).

### Go

```bash
go get github.com/agent-receipts/ar/sdk/go
```

```go
import "github.com/agent-receipts/ar/sdk/go/receipt"

keys, _ := receipt.GenerateKeyPair()
unsigned := receipt.Create(receipt.CreateInput{
    Issuer:    receipt.Issuer{ID: "did:agent:my-agent"},
    Principal: receipt.Principal{ID: "did:user:alice"},
    Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
    Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
    Chain:     receipt.Chain{Sequence: 1, ChainID: "chain_1"},
})
signed, _ := receipt.Sign(unsigned, keys.PrivateKey, "did:agent:my-agent#key-1")
```

### TypeScript

```bash
npm install @obsigna/sdk-ts
```

```typescript
import {
  createReceipt,
  generateKeyPair,
  signReceipt,
} from "@obsigna/sdk-ts";

const keys = generateKeyPair();
const unsigned = createReceipt({
  issuer: { id: "did:agent:my-agent" },
  principal: { id: "did:user:alice" },
  action: { type: "filesystem.file.read", risk_level: "low" },
  outcome: { status: "success" },
  chain: { sequence: 1, previous_receipt_hash: null, chain_id: "chain_1" },
});
const signed = signReceipt(unsigned, keys.privateKey, "did:agent:my-agent#key-1");
```

### Python

```bash
pip install obsigna
```

```python
from obsigna import (
    create_receipt, generate_key_pair, sign_receipt,
    CreateReceiptInput, Issuer, Principal, Outcome, Chain,
)
from obsigna.receipt.create import ActionInput

keys = generate_key_pair()
unsigned = create_receipt(CreateReceiptInput(
    issuer=Issuer(id="did:agent:my-agent"),
    principal=Principal(id="did:user:alice"),
    action=ActionInput(type="filesystem.file.read", risk_level="low"),
    outcome=Outcome(status="success"),
    chain=Chain(sequence=1, previous_receipt_hash=None, chain_id="chain_1"),
))
signed = sign_receipt(unsigned, keys.private_key, "did:agent:my-agent#key-1")
```

See the [Python SDK README](sdk/py/README.md) for the full quick start and daemon delivery.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities. The [threat model](docs/threat-model.md) documents trust boundaries, in-scope and out-of-scope threats, and the mitigation roadmap.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
The protocol specification in `spec/` is licensed under MIT.
