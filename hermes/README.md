<div align="center">

# agent-receipts-hermes

### Agent Receipts plugin for [hermes-agent](https://github.com/NousResearch/hermes-agent)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)

---

Cryptographically signed, hash-linked audit trail for every tool call a
hermes-agent makes.

Built on [`agent-receipts`](../sdk/py) (Python SDK) and the
[agent-receipts daemon](../daemon).

[Spec](../spec) &bull; [Python SDK](../sdk/py) &bull; [OpenClaw plugin](https://github.com/agent-receipts/openclaw)

</div>

---

> **Status:** experimental POC. The plugin's wire path (pre/post hooks →
> daemon over AF\_UNIX) is exercised end-to-end in tests; the
> agent-callable tools (`ar_query_receipts`, `ar_verify_chain`) are
> wired into hermes via best-effort introspection of the host `ctx` and
> may need adjustment once the hermes plugin API for tool registration
> is documented upstream.

---

## What it looks like

After a session where the agent reads a file, runs a command, and
fetches a URL, querying the audit trail returns:

```json
{
  "total_receipts": 3,
  "total_chains": 1,
  "by_risk":   [{ "risk_level": "low",  "count": 2 }, { "risk_level": "high", "count": 1 }],
  "by_status": [{ "status": "success", "count": 3 }],
  "results": [
    { "id": "urn:receipt:…03", "action": "system.browser.navigate", "risk": "low",  "target": "https://example.com", "status": "success", "sequence": 3 },
    { "id": "urn:receipt:…02", "action": "system.command.execute",  "risk": "high", "target": "echo hi",            "status": "success", "sequence": 2 },
    { "id": "urn:receipt:…01", "action": "filesystem.file.read",    "risk": "low",  "target": "/etc/hosts",         "status": "success", "sequence": 1 }
  ]
}
```

Verifying the chain confirms nothing was tampered with:

```
Chain "chain_hermes_main" is valid: 3 receipts, all signatures and hash links verified.
```

Every receipt is a signed [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) —
parameters are hashed by default, and each receipt is hash-linked to the
previous one, forming a tamper-evident chain.

## How it works

Every time the hermes agent executes a tool, this plugin:

1. **Classifies the action** using the [Agent Receipts taxonomy](../spec/taxonomy).
2. **Forwards an unsigned frame** to the local [agent-receipts daemon](../daemon) over AF\_UNIX.
3. The daemon **signs, hash-links, and stores** the receipt in its SQLite database.

The agent also gets two introspection tools to query and verify its own
audit trail.

```
hermes plugin manager
  │
  ├─ pre_tool_call  ──► classify → forward "pending" frame to daemon
  │
  ├─ [tool executes]
  │
  └─ post_tool_call ──► forward "allowed" frame to daemon
                            │
                       daemon: sign → chain → store
```

> **The daemon is required.** Frames are forwarded fire-and-forget — if
> the socket is unreachable, a startup warning is logged and delivery
> drops silently until the daemon is reachable. No receipts are recorded
> while the daemon is absent.

## Install

The plugin ships as a regular Python package. Once installed alongside
your hermes-agent runtime, it needs to be visible to hermes' plugin
discovery — either drop the package directory into your hermes plugins
tree or symlink it.

```sh
# 1. Install the plugin module into the same Python environment hermes
#    runs from.
pip install agent-receipts-hermes
# (or, from a checkout)
uv pip install -e .

# 2. Symlink the installed package into hermes' plugin tree.
HERMES_ROOT=~/.hermes/repo
mkdir -p "$HERMES_ROOT/plugins/observability"
ln -sf \
  "$(python -c 'import os, agent_receipts_hermes; print(os.path.dirname(agent_receipts_hermes.__file__))')" \
  "$HERMES_ROOT/plugins/observability/agent-receipts"

# 3. Activate the plugin.
hermes plugins enable observability/agent-receipts
```

Alternatively copy `src/agent_receipts_hermes/` straight into
`<hermes>/plugins/observability/agent-receipts/` — the directory layout
already matches what hermes expects (`__init__.py` exporting
`register(ctx)`, plus `plugin.yaml`).

See [Daemon setup](#daemon-setup) below for the agent-receipts daemon
itself.

## CLI — Receipt Explorer

Query and verify receipts outside of agent sessions:

```sh
# List all receipts (table output).
agent-receipts-hermes receipts

# Filter by risk level and emit JSON.
agent-receipts-hermes receipts --risk high --json

# Verify every chain in the daemon database.
agent-receipts-hermes verify

# Verify a specific chain.
agent-receipts-hermes verify --chain chain_hermes_main_sid-42

# Export a single receipt or a whole chain as JSON-LD.
agent-receipts-hermes export --id urn:receipt:abc-123
agent-receipts-hermes export --chain chain_hermes_main_sid-42 --format presentation
```

Run `agent-receipts-hermes --help` for the full option list.

## Agent tools

### `ar_query_receipts`

Search the audit trail by action type, risk level, or outcome status.
Returns receipt summaries and aggregate stats, newest-first across all
sessions.

### `ar_verify_chain`

Cryptographically verify the integrity of the daemon's receipt chain —
Ed25519 signatures, hash links, and sequence numbering. Auto-selects
the most recent chain when `chain_id` is omitted.

## Taxonomy

The plugin maps common hermes tool names to Agent Receipts action types.
A subset:

| hermes tool         | Action type                  | Risk    |
|:--------------------|:-----------------------------|:--------|
| `read_file`         | `filesystem.file.read`       | low     |
| `write_file`        | `filesystem.file.create`     | low     |
| `edit_file`         | `filesystem.file.modify`     | medium  |
| `delete_file`       | `filesystem.file.delete`     | high    |
| `bash` / `shell`    | `system.command.execute`     | high    |
| `web_fetch`         | `system.browser.navigate`    | low     |
| `browser_click`     | `system.browser.form_submit` | medium  |
| `send_message`      | `system.application.control` | medium  |
| `memory_store`      | `filesystem.file.create`     | low     |
| `subagent_spawn`    | `system.command.execute`     | high    |

See [`src/agent_receipts_hermes/taxonomy.json`](src/agent_receipts_hermes/taxonomy.json)
for the full mapping. Override with a custom file via the
`taxonomyPath` config option.

## Configuration

All settings are optional — the plugin works out of the box with sensible
defaults, assuming the daemon is installed at its default paths.

| Setting              | Default                | Description |
|:---------------------|:-----------------------|:------------|
| `enabled`            | `true`                 | Forward tool calls to the daemon. |
| `socketPath`         | *(platform default)*   | Path to the daemon socket (overrides `AGENTRECEIPTS_SOCKET`). |
| `daemonDbPath`       | *(platform default)*   | Path to the daemon's SQLite database (overrides `AGENTRECEIPTS_DB`). |
| `daemonPublicKeyPath`| *(platform default)*   | Path to the daemon's Ed25519 public key PEM. |
| `taxonomyPath`       | *(bundled)*            | Custom tool → action-type mapping. |
| `channel`            | `hermes`               | Channel identifier embedded in every frame. |

Default paths follow the daemon's own resolution: `AGENTRECEIPTS_DB` env
var → `$XDG_DATA_HOME/agent-receipts/receipts.db` →
`~/.local/share/agent-receipts/receipts.db`.

Example `plugin.yaml` overrides (passed through hermes' config layer):

```yaml
config:
  enabled: true
  # taxonomyPath: /path/to/custom-taxonomy.json
  # daemonDbPath: /custom/path/receipts.db
  # daemonPublicKeyPath: /custom/signing.key.pub
```

## Daemon setup

The [agent-receipts daemon](../daemon) must be installed and running
locally. Per ADR-0010 the daemon is the single owner of signing keys,
canonical hashing, and chain state.

**macOS (Homebrew):**

```sh
brew install agent-receipts/tap/agent-receipts-daemon
brew services start agent-receipts-daemon
```

**Linux:**

```sh
curl -fsSL https://github.com/agent-receipts/ar/releases/latest/download/install.sh | sh
sudo loginctl enable-linger $USER
```

See [daemon setup docs](https://agentreceipts.ai/getting-started/daemon-setup/)
for the full reference.

## Development

```sh
uv sync --all-extras
uv run pytest -v
uv run ruff check .
uv run pyright src
```

| | |
|:---|:---|
| **Language** | Python ≥ 3.11, strict pyright |
| **Testing** | pytest |
| **Runtime deps** | `agent-receipts` (Python SDK) |

## Ecosystem

| Repository | Description |
|:---|:---|
| [agent-receipts/spec](../spec) | Protocol specification, JSON schemas, taxonomy |
| [agent-receipts/sdk-py](../sdk/py) | Python SDK |
| [agent-receipts/sdk-ts](../sdk/ts) | TypeScript SDK |
| [agent-receipts/openclaw](https://github.com/agent-receipts/openclaw) | OpenClaw plugin |
| **agent-receipts/ar/hermes** (this plugin) | hermes-agent integration |
| [agent-receipts/ar/mcp-proxy](../mcp-proxy) | MCP proxy + CLI |

## License

Apache License 2.0 — see [LICENSE](../LICENSE).
