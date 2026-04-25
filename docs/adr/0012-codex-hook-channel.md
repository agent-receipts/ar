# ADR-0012: codex_hook Emission Channel

## Status

Proposed

## Context

Codex CLI exposes a hooks system structurally similar to Claude Code's: `PreToolUse` and `PostToolUse` lifecycle hooks fire around tool invocations and can observe — and in the `Pre` case veto — a tool call before it runs. From the agent-receipts point of view that is the same shape we already exploit for the `claude_code_hook` channel: a stable interception point, controlled by the user, with structured event data we can convert into a receipt.

Two things make Codex materially different from Claude Code, and they pull the design in opposite directions:

1. **Codex enforces kernel-level sandboxing.** On macOS, Codex confines tool execution under Apple Seatbelt; on Linux, under Landlock/seccomp. The sandbox is the primary enforcement boundary — it is what actually prevents a tool call from touching the filesystem or network outside its policy. Hooks are supplementary: they observe and can advise, but the kernel is what stops the action. This is the inverse of the Claude Code story, where the hook (or the MCP proxy) is itself the enforcement point.

2. **Codex hook coverage is incomplete by design, and the gaps are not the same gaps Claude Code has.** Per OpenAI's published hooks documentation, Codex `PreToolUse`/`PostToolUse` hooks fire around:
   - `Bash` tool calls
   - `apply_patch` tool calls
   - MCP tool calls

   They do **not** fire around `WebSearch`, and they do **not** fire around every shell invocation: the hook integration is wired up for "simple" shell calls only, and `unified_exec` interception is documented as incomplete. A receipt chain built from Codex hooks therefore has known, structural blind spots that are different from the blind spots in a claude_code_hook chain (which has its own; see ADR-0011 once landed).

The combination — supplementary-rather-than-primary enforcement, plus a different coverage envelope — means Codex hooks cannot be quietly folded into the existing `claude_code_hook` channel. A verifier that did so would silently widen its trust in the chain: receipts would appear comparable across vendors when in fact each vendor's chain elides a different set of events.

## Decision

Define `codex_hook` as a **separate emission channel**, peer to `claude_code_hook`, `mcp_proxy`, `openclaw`, and `sdk` in the ADR-0010 schema split. The channel discriminator carries the trust statement: a `codex_hook` receipt means "observed via Codex's hook system, with Codex's coverage envelope," and nothing more.

### Events that emit receipts

`codex_hook` emits one receipt per Codex hook invocation that the daemon receives, for the documented covered tool surface:

- `Bash` (`PreToolUse` and `PostToolUse`)
- `apply_patch` (`PreToolUse` and `PostToolUse`)
- MCP tool calls (`PreToolUse` and `PostToolUse`)

`PreToolUse` receipts carry `decision = allowed | denied | pending`; `PostToolUse` receipts carry the tool's `output` and/or `error` and finalise `decision`. Pre/Post for the same call are linked through `session_id` plus a per-call correlator carried in the event body, exactly as for `claude_code_hook`.

`WebSearch` and any shell invocation that bypasses the hooks integration (notably `unified_exec` paths) **do not** emit `codex_hook` receipts — they cannot, because no hook fires.

### Coverage gap is recorded in the receipt, not just in the ADR

The chain itself must make the blind spot machine-readable so a verifier does not have to know the contents of this ADR to interpret a chain correctly. Two parts:

1. **Channel discriminator.** `channel = "codex_hook"` is by itself a coverage statement: anyone consuming the chain can look up the channel's documented coverage envelope (this ADR) and apply the appropriate trust calculus. No `claude_code_hook` receipt can be mistaken for a `codex_hook` receipt or vice versa.
2. **Per-receipt coverage metadata.** Each `codex_hook` event carries an explicit `coverage` block in the emitter-supplied payload — for example, `{ "covers": ["Bash", "apply_patch", "mcp"], "excludes": ["WebSearch", "unified_exec"], "enforcement": "advisory", "sandbox": "seatbelt" | "landlock_seccomp" | "none" }`. The daemon canonicalises and signs this alongside the rest of the event, so the gap statement is itself attested. Verifiers MUST treat the absence of a `codex_hook` receipt for `WebSearch` or `unified_exec` activity as expected, not as evidence of suppression — and the `coverage.excludes` list is what tells them which absences are expected for this chain.

This is deliberately different from the `claude_code_hook` channel, which has its own (different) coverage envelope. Verifiers comparing chains across vendors must read the `channel` and `coverage` fields and reason per-channel; the daemon does not paper over the difference.

### Drop-counter handling

Codex hooks are short-lived processes, the same problem `claude_code_hook` faces: a hook that fires, drops events on `EAGAIN`, and exits before it can flush the drop counter loses the gap signal in the narrow window between `EAGAIN` and process exit.

**Reuse the ADR-0010 mechanism unchanged.** The emitter increments a local drop counter on `EAGAIN`, flushes it alongside the next successful event, and the daemon synthesises an `events_dropped` receipt into the chain so the gap is visible. The same narrow loss window — emitter crash after drop, before flush — applies and is documented as such. We deliberately do not invent a second drop mechanism for Codex; one mechanism, one set of failure modes, one set of verifier expectations across all hook-style channels.

A second mechanism would be tempting (Codex hooks could, for instance, persist their drop counter to a small per-session file before exit) but would (a) fork the verifier's mental model and (b) create a second class of "did the gap get recorded" bug we'd have to maintain. The single-mechanism property is more valuable than the marginal reduction in the loss window.

### Packaging

Codex's hook integration story is thinner than Claude Code's plugins: hooks are wired up declaratively via Codex's `config.toml` rather than installed as a plugin bundle with its own manifest, lifecycle, and update channel. The agent-receipts integration matches that thinness:

- Distribute a small standalone emitter binary (`agent-receipts-codex-hook`), built per-platform and shipped through the same channel as the daemon (Homebrew, `.deb`/`.rpm`, Windows installer per ADR-0010).
- Distribute a config snippet for `config.toml` that wires `PreToolUse` and `PostToolUse` to that binary for the covered tool surface.
- The binary is a thin emitter in the ADR-0010 sense: it captures the hook's structured event, fires it over the daemon's IPC socket, and exits. No signing, no storage, no crypto — those live in the daemon.

Packaging is intentionally not a plugin bundle. Codex does not have the plugin infrastructure to make that pay off, and forcing one would mean inventing lifecycle, update, and versioning machinery that the host CLI does not provide.

## Consequences

### Positive

- Covers the Codex user base under the same chain, daemon, and verification story as Claude Code, MCP proxy, and the SDKs — receipts from a developer using both CLIs end up in one chain with monotonic `seq` and shared `session_id` grouping.
- Reuses ADR-0010's daemon, IPC transport, peer-credential capture, canonicalisation, and signing without modification. No new crypto, no new schema, no new socket. The emitter binary is small precisely because all of that is already solved.
- Reuses the ADR-0011-style drop-counter mechanism, so the verifier's mental model for hook-style channels is consistent: `events_dropped` receipts mean the same thing whether the gap originated in a Codex hook or a Claude Code hook.
- Encodes the coverage gap structurally — in the `channel` discriminator and in a signed per-receipt `coverage` block — instead of relying on out-of-band documentation. A verifier that has never read this ADR can still compute the right trust statement.
- Packaging is light: a binary plus a config snippet rather than a plugin manifest, matching what Codex actually offers.

### Negative / tradeoffs

- **Coverage is incomplete by design.** `WebSearch` and `unified_exec` activity does not appear in the chain at all from this channel. This is a property of Codex, not of agent-receipts, but the implication for users is real: a `codex_hook`-only chain is not a complete record of the agent's tool use, and we must not market it as one.
- **Verifiers must treat `codex_hook` chains differently from `claude_code_hook` chains.** The two channels have different coverage envelopes and different enforcement properties (Codex sandbox is primary; Claude Code hook is closer to primary). Anything in the verification or dashboard layer that compares vendors must read the `channel` discriminator and the per-receipt `coverage` block; it cannot treat all hook-derived receipts as equivalent.
- **Hooks are supplementary, not primary, enforcement.** A `codex_hook` `decision = denied` receipt records that the hook said "no"; the actual stop, in most realistic scenarios, came from Seatbelt or Landlock/seccomp at the kernel layer. The receipt is honest about what it is — an observation at the hook layer — and verifiers should not infer enforcement strength from the channel alone.
- **Two channels for "the agent's CLI hooks" rather than one.** This is the right tradeoff (the channels really are different) but it is more channels for the dashboard, the docs, and any cross-channel correlation logic to know about. Adding a third hook-style channel later (some other CLI) would be straightforward — that is the point of channel separation — but the surface area grows linearly.

## Related ADRs

- [ADR-0010 (Daemon Process Separation)](./0010-daemon-process-separation.md) — defines the channel field, the daemon, the IPC transport, the peer-credential capture, and the drop-counter / `events_dropped` mechanism this ADR reuses.
- ADR-0011 (`claude_code_hook` Emission Channel) — peer channel for Claude Code's hooks; this ADR mirrors its channel-extension pattern and deliberately diverges on coverage and packaging where Codex differs.
- [ADR-0008 (Response Hashing and Chain Completeness)](./0008-response-hashing-and-chain-completeness.md) — chain-completeness reasoning that motivates recording coverage gaps in-chain rather than only in documentation.
- [ADR-0009 (Canonicalisation Profile and VC Field Name Commitment)](./0009-canonicalization-and-schema-consistency.md) — the `coverage` block is part of the signed event body and is canonicalised under this profile.
