# ADR-0013: claude_code_hook Emission Channel

## Status

Proposed

## Context

[ADR-0010](./0010-daemon-process-separation.md) establishes the thin-emitter / daemon split and enumerates the emitter channel space as `channel: openclaw | mcp_proxy | sdk | ...`, explicitly anticipating additional channels as new agent surfaces are integrated. This ADR adds one such channel.

Claude Code is Anthropic's coding agent. Distinct from `openclaw` (which instruments the Claude SDK at the loop level) and `mcp_proxy` (which instruments MCP traffic on the wire), Claude Code exposes a first-class hook system that fires on every tool invocation across its full tool surface — `Bash`, `Edit`, `Write`, `Read`, `WebFetch`, `WebSearch`, the Task subagent, and every connected MCP server. The relevant hook events for receipt emission are:

- **PreToolUse** — fires before a tool call, with the tool name and resolved input arguments. Hooks can permit, block, or annotate the call. Maps to ADR-0010 `decision`.
- **PostToolUse** — fires after a tool call returns, with the input and the result/error. Maps to ADR-0010 `output` / `error`.
- **SessionStart** — fires once at the beginning of an agent run, carrying a stable `session_id`. Aligns with ADR-0010 `session_id` scoping.
- **UserPromptSubmit** — fires when the user submits a prompt, before the model sees it. Useful as a session-scope context marker but does not itself describe a tool call.

Hooks are configured per-project or per-user as JSON. Each registered hook is a short-lived shell command that receives a JSON payload on stdin describing the event and writes a JSON response (or nothing) on stdout. The process is forked, given a configurable timeout (Claude Code's default is 600s for command hooks), and reaped. This shape is a natural fit for the ADR-0010 thin emitter: open the daemon socket, write one event, exit.

Two properties of this channel matter for the ADR-0010 design:

1. **Coverage**. A single hook registration captures every tool call Claude Code makes — including MCP traffic that an `mcp_proxy` instance also captures, and including tools (`Bash`, `Edit`, `Write`, file reads, web fetches) that no other channel sees today. This is the broadest single-emitter tool-surface integration available.
2. **Process lifetime**. Unlike `openclaw` (long-lived in the agent process) or `mcp_proxy` (long-lived as a server), each hook invocation is a fresh process. The local drop-counter mechanism in ADR-0010 — "increment on `EAGAIN`, flush alongside the next successful event from the same emitter" — has no in-memory continuity to rely on. This is the open hook-channel backpressure issue called out in ADR-0010's drop-tracking model.

## Decision

Define `claude_code_hook` as a new `channel` value in the ADR-0010 emitter schema and ship a Claude Code plugin that registers an emitter on the relevant hook events.

### Channel value and event mapping

The emitter sets `channel: "claude_code_hook"`. Hook events map to emitter→daemon IPC fields as follows:

| Hook event        | Emits receipt? | Emitter→daemon IPC fields populated                                                       |
|-------------------|----------------|-------------------------------------------------------------------------------------------|
| `SessionStart`    | No (no-op for emitter) | The per-invocation emitter has no in-process state to retain between hook firings; `session_id` arrives unchanged in every subsequent hook payload. The hook is registered for plugin completeness, and the emitter MAY use this firing to opportunistically prune stale drop files (see drop-counter handling), but otherwise exits immediately. |
| `UserPromptSubmit`| Optional (off by default) | If enabled: `tool: { name: "user_prompt" }`, `input: { prompt }`, `decision: "allowed"`. |
| `PreToolUse`      | Yes            | `tool: { name, server? }`, `tool_use_id` (per-invocation identifier from the hook payload), `input` (raw tool args), `decision` (`allowed` if the hook returns permit; `denied` if the hook returns block; `pending` for async or undecided cases). `output`/`error` empty. |
| `PostToolUse`     | Yes            | Same `tool`, `tool_use_id`, and `input` as the matching PreToolUse, plus `output` or `error` from the tool result. `decision` reflects the executed outcome. |

The fields above describe the **emitter→daemon IPC payload**, not the persisted receipt. Raw hook payloads (`input`, `output`, `error`, and any optional `prompt`) are transient IPC input only. The daemon canonicalizes (RFC 8785 per ADR-0002), hashes (`parameters_hash` and `response_hash` per ADR-0008), and applies redaction policy before persisting or signing. `UserPromptSubmit`, when enabled, is governed by the daemon's prompt-redaction policy; the full prompt MUST NOT be persisted in plaintext. IPC frame sizing is the daemon's responsibility per ADR-0010; `UserPromptSubmit` payloads in particular can be multi-megabyte (pasted logs, file contents) and the daemon's IPC framing limit, not the emitter, governs what is accepted.

Pre/Post pairs MUST share `session_id`, `tool_use_id`, and tool identity so the daemon (and verifiers) can correlate them deterministically. `session_id` plus tool identity alone is insufficient because the same tool may be invoked many times in one session (e.g., repeated `Bash` calls); the per-invocation `tool_use_id` from Claude Code's hook payload is the unambiguous pairing key. The pairing itself is the daemon's job, but the emitter MUST surface `tool_use_id` on both events. For MCP tools surfaced through Claude Code, the hook payload's `tool_name` is namespaced as `mcp__<server>__<tool>`; the emitter MUST split this into `tool.name` and `tool.server` so the receipt shape matches what `mcp_proxy` produces for the same call. (Cross-channel duplication is expected and intentional under ADR-0010's single-chain model — both receipts land in the chain with the same `session_id`, distinguished by `channel` and by the daemon-attested `peer`. Verifiers reconciling the two views match on `session_id` + tool identity (`tool.name` + `tool.server`) + `parameters_hash`; `tool_use_id` is not a cross-channel correlation key because `mcp_proxy` observes only the MCP wire-level call ID, not Claude Code's internal `tool_use_id`.)

### Session scoping

The emitter MUST use the `session_id` Claude Code provides in the hook input payload as the ADR-0010 `session_id`. Claude Code's session ID is the authoritative scope marker for one agent run on this channel: it is generated by the client at session creation, persists across every hook invocation within that session, and is the same identifier the user sees in `~/.claude` transcript paths. Generating a fresh UUID per emitter invocation would shatter one Claude Code session into N single-event sessions and defeat the cross-channel correlation property ADR-0010 sets up. The Claude Code session ID is a UUID and slots into the ADR-0010 schema unchanged.

### Drop-counter handling

ADR-0010 assumes an emitter can hold a drop counter in memory and flush it alongside its next successful event. A fresh-process-per-event emitter has no such continuity: every drop is the last drop that process will ever see. Resolving this is the open hook-channel backpressure issue this ADR closes.

The emitter MUST persist drop counts to a per-session file in the platform runtime directory and MUST flush any accumulated count on its next successful send.

- Linux: `$XDG_RUNTIME_DIR/agentreceipts/drops/<session_id>` (falling back to `/run/user/<uid>/agentreceipts/drops/<session_id>` if `XDG_RUNTIME_DIR` is unset).
- macOS: `$TMPDIR/agentreceipts/drops/<session_id>` (per-user, tmpwatch-eligible).
- Windows: `%LOCALAPPDATA%\agentreceipts\drops\<session_id>`.

Files are created so that only the invoking user can read or modify them: POSIX mode `0600` on Linux and macOS, and an equivalent user-only ACL on Windows (the security descriptor must grant access to the invoking user SID only — no `Authenticated Users` or `Everyone` ACEs). They are owned by the invoking user and contain a single integer count. The emitter's behaviour on each invocation:

1. Connect to the daemon socket non-blocking. If connect fails (daemon not running): exit silently — ADR-0010 already classifies this as the "events drop silently" mode, and a fresh emitter cannot record what it has no channel to record.
2. Acquire an exclusive advisory lock on a sibling lockfile `<session_id>.lock` in the same directory (`flock(LOCK_EX)` on POSIX, `LockFileEx` on Windows). The lock is held across steps 3–6 to serialise concurrent emitter invocations within the same session — Claude Code can fire `PreToolUse`/`PostToolUse` hooks for parallel tool calls overlappingly. Acquisition uses a short timeout (≤50ms suggested); on timeout, proceed without the lock and accept best-effort drop accounting. The lock guards bookkeeping only and is never required for IPC correctness.
3. Read the per-session drop file if it exists, capturing the count, but **leave the file in place** until a successful send.
4. Compose the event with a new `drop_count` field carrying any pre-existing count from step 3.
5. Send the event. On `EAGAIN`: atomically update the per-session drop file to `previous_count + 1` by writing the new integer to a temp file in the same directory and `rename()`-ing it over the session file, then release the lock and exit.
6. On successful send: unlink the per-session drop file if one existed, release the lock, and exit. The daemon, on receiving an event with `drop_count > 0`, synthesises an `events_dropped` receipt in the chain exactly as ADR-0010 specifies for the in-memory case.

The "leave-until-success" ordering plus the temp-file-and-rename update guarantee that a crash or kill between any two steps cannot lose the count: the file is only removed after the daemon has acknowledged the bundled `drop_count`, and `EAGAIN` updates are atomic with respect to power loss. The advisory lock prevents concurrent emitters in the same session from both reading count=N, both successfully sending (each carrying `drop_count=N`), and the second emitter unlinking the file that the first had just written `N+1` to. With the local socket sending sub-millisecond, the lock window is tight enough that the 50ms timeout fallback is a true edge case rather than a hot path.

### IPC contract additions

This channel introduces two additions to the ADR-0010 emitter→daemon IPC contract — one channel-specific, one cross-channel:

- `tool_use_id: string` — **channel-specific**, required on `PreToolUse` and `PostToolUse` events for `claude_code_hook`. The emitter MUST forward the top-level `tool_use_id` field from Claude Code's hook input payload (see [Claude Code hooks documentation](https://code.claude.com/docs/en/hooks)). Per the documented schema, `tool_use_id` is present on both `PreToolUse` and `PostToolUse` and remains constant across the pair for the same invocation; it is absent on `SessionStart` and `UserPromptSubmit`. The daemon uses it together with `session_id` to pair Pre/Post deterministically. Other channels are not required to populate this field.
- `drop_count: non-negative integer` — **cross-channel**, optional, default 0, omitted when zero. Any emitter may set it. Existing emitters that hold the counter in memory may set this field instead of relying on a follow-up flush, simplifying their implementation. This is a strict superset of the current contract.

A residual loss window remains, narrower than but analogous to ADR-0010's: if the runtime directory itself is wiped between hook invocations (reboot, manual cleanup of `$XDG_RUNTIME_DIR`), pending drop counts for that session are lost. This is documented and considered acceptable — runtime-directory wipes already terminate the session in every meaningful sense.

A separate concern is *file accumulation*. A session that ends with a dropped event (no successor to flush the count) leaves its drop file behind. Linux clears `$XDG_RUNTIME_DIR` at logout/reboot; macOS reaps stale entries from `$TMPDIR` via the OS's periodic tmp-cleanup; Windows `%LOCALAPPDATA%` has no equivalent automatic sweep. The emitter SHOULD opportunistically prune drop files older than 24 hours from the runtime drops directory — for example, on `SessionStart` firings (where the emitter would otherwise exit immediately) or as a best-effort step early in any invocation. A missed sweep cannot corrupt count integrity (older files belong to unrelated sessions) and only delays reclamation.

### Packaging

The integration ships as a Claude Code plugin:

- A `.claude-plugin/plugin.json` manifest declaring metadata (name, version, author).
- A `hooks/hooks.json` declaring `PreToolUse`, `PostToolUse`, `SessionStart`, and (optionally) `UserPromptSubmit` entries. Matchers are unrestricted (`"*"`) so the channel covers Claude Code's full tool surface. Each entry's `command` invokes a single emitter binary with the hook event name as argv — `agentreceipts-claude-hook <event>` — keeping the per-event configuration to one line per hook.
- The emitter is a small single-binary tool implemented in Go, matching `mcp_proxy`'s language so the two share the ADR-0010 IPC client implementation. A single statically-linked binary is the right deployment shape: hooks fire on every tool call and any user-visible latency added on the hot path degrades interactive UX (see the latency tradeoff under Consequences). A scripting-language emitter would pay interpreter-startup cost on every tool call.
- The plugin distributes prebuilt binaries for Linux (amd64, arm64), macOS (arm64, amd64), and Windows (amd64), and falls back to a clear error if the architecture is unsupported.

### Trust model

Identical to any other thin emitter under ADR-0010. The daemon captures peer credentials at connection-accept time via `SO_PEERCRED` / `LOCAL_PEERCRED` / `GetNamedPipeClientProcessId` and attests the emitter process directly: PID, UID/SID, executable path. The agent's self-asserted identity is not trusted.

This is a single attestation layer, unlike `mcp_proxy`'s two-layer model. The emitter is invoked synchronously by Claude Code — Claude Code is the parent process. The daemon's peer attestation lands on the emitter binary, but the emitter's parent process (Claude Code itself) is recoverable from the captured PID via `/proc/<pid>/status` (Linux), `proc_pidinfo` (macOS), or `NtQueryInformationProcess` (Windows). Recording the parent identity in the receipt's `peer` object is a daemon-side concern out of scope for this ADR; the relevant property here is that no proxy or shim sits between Claude Code and the emitter, so peer credentials are an honest read of the agent process's child.

## Consequences

### Positive

- Broadest single-emitter coverage of any channel: a single plugin registration captures Claude Code's full tool surface — `Bash`, file edits, web fetches, Task subagents, and every MCP server it talks to — closing surface gaps that `mcp_proxy` (MCP-only) and `openclaw` (SDK-loop-only) leave open.
- Natural fit for the ADR-0010 thin-emitter model: hooks are already short-lived shell commands handed JSON on stdin, exactly the shape ADR-0010 prescribes. No adapter layer.
- Shares the ADR-0010 single chain, single canonicalizer, single key with `openclaw` and `mcp_proxy`. Cross-channel correlation by `session_id` works out of the box; an MCP call observed by both `mcp_proxy` and `claude_code_hook` produces two receipts in the same chain with the same `session_id`, attested through different peer credentials.
- Closes the open hook-channel backpressure question raised in ADR-0010, and the resulting `drop_count` IPC field tightens the contract for all emitters, not just this one.
- Single-layer peer attestation. Unlike `mcp_proxy`, no proxy-attests-agent layer is needed; the daemon's peer creds land directly on a child of Claude Code.

### Negative / tradeoffs

- Channel is Claude Code-specific. It does not generalise to other agents that lack a comparable hook system — those will need their own channels. This is consistent with ADR-0010's `channel: ...` enumeration but means each major agent surface needs bespoke integration work.
- Coverage is enforced by the client. A user can disable or skip the plugin; ADR-0010's daemon cannot detect "Claude Code ran without the hook plugin loaded." Receipts establish what was claimed and signed, not that all activity was reported on this channel. This is the same property `openclaw` has, but worth naming because the breadth of coverage makes it tempting to overstate.
- Drop-visibility mechanism is more complex than for long-lived emitters: a per-session file plus an IPC field, where ADR-0010's current emitters need only an in-process counter. Operationally this means one more place where state can be lost (the runtime directory) and one more contract for verifiers to understand (the `drop_count` field).
- Per-invocation startup latency is on the hook critical path. Claude Code's default hook timeout is 600s, so the constraint is not the configured budget but UX: any latency added on the hot path is user-visible on every tool call. The Go-binary choice — single statically-linked binary, sub-millisecond startup — is a tradeoff in service of this UX constraint, at the cost of language uniformity with the SDK ecosystem.
- Volume profile is significantly higher than other channels. This channel emits 2 events per tool call (Pre + Post) across Claude Code's full tool surface, including frequently-invoked tools (`Bash`, `Read`, `Edit`). A typical Claude Code session can produce hundreds of receipts. The daemon's signing/fsync model from ADR-0010 must remain headroom-comfortable at this rate; this channel will be the dominant per-session load on the daemon for typical workloads.
- Adds packaging surface: a Claude Code plugin distribution alongside the npm SDK, the daemon system service, and the `mcp_proxy` binary. This is in line with ADR-0010's "packaging story required" tradeoff but extends it to a fourth artifact.

## Related ADRs

- [ADR-0010 (Daemon process separation)](./0010-daemon-process-separation.md) — defines the thin-emitter / daemon split, the channel enumeration this ADR extends, and the IPC contract this ADR adds a `drop_count` field to.
- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — unchanged; the daemon remains the sole signer.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — unchanged; canonicalization happens only in the daemon, never in the hook emitter.
