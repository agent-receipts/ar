# agent-receipts-hook

Short-lived hook binary for [Agent Receipts](https://github.com/agent-receipts/ar). Invoked by agent runtimes on `PostToolUse` events — reads a JSON frame from stdin, maps it to an audit event, and forwards it to `agent-receipts-daemon` over a Unix-domain socket. It exits 0 silently when the frame is unreadable or the runtime isn't recognised; once the runtime is identified, a failure to record the receipt exits 1 with a stderr message (surfacing a broken audit pipeline rather than dropping receipts). It never pauses or modifies the tool call.

## Install

```bash
brew install agent-receipts/tap/agent-receipts-hook
# or
go install github.com/agent-receipts/ar/hook/cmd/agent-receipts-hook@latest
```

Requires `agent-receipts-daemon` to be running to capture events.

## Claude Code setup

In your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "agent-receipts-hook"
          }
        ]
      }
    ]
  }
}
```

## Supported runtimes

| Runtime | Detection | Format flag |
|---------|-----------|-------------|
| Claude Code | `CLAUDE_SESSION_ID` env var | `--format claude-code` |

Auto-detection runs when `--format` is unset. Use `--format` to force a specific format.

## License

Apache-2.0 — see [LICENSE](../LICENSE).
