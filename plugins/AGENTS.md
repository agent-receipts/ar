# AGENTS.md

Third-party agent-runtime integrations for Agent Receipts — plugins that run
**inside someone else's agent runtime** and forward tool-call frames to the
local agent-receipts daemon.

This is distinct from the first-party binaries Agent Receipts ships itself
(`hook`, `mcp-proxy`, `daemon`, `collector`), which live at the repo root. The
criterion for living here: *does this code load and run inside a foreign agent
host?* If yes, it is a plugin.

## Layout

```
plugins/
  hermes/   # Plugin for the hermes-agent runtime (Python)
```

(`openclaw` is documented under `site/` and lives in its own repo today; if it
is ever vendored in-tree, it belongs here too.)

## Conventions

- Each plugin is a self-contained, independently published package with its
  own `AGENTS.md`, `CHANGELOG.md`, and toolchain.
- Each plugin has a path-filtered CI workflow (`.github/workflows/<name>.yml`)
  that runs only on changes under `plugins/<name>/**`.
- Plugins depend on the **published** Agent Receipts SDK (e.g. the
  `agent-receipts` PyPI wheel), not the in-tree `sdk/`, unless a plugin's own
  `AGENTS.md` says otherwise. A plugin that pins the published SDK will not be
  exercised against in-tree `sdk/` changes — keep that divergence in mind.
- See each plugin's `AGENTS.md` for its commands, architecture, and rules.
