# ADR-0014: codex_hook Emission Channel

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

   They do **not** fire around `WebSearch`, and they do **not** fire around every shell invocation: the hook integration is wired up for "simple" shell calls only, and `unified_exec` interception is documented as incomplete. A receipt chain built from Codex hooks therefore has known, structural blind spots that are different from the blind spots in a claude_code_hook chain (which has its own; see ADR-0013).

The combination — supplementary-rather-than-primary enforcement, plus a different coverage envelope — means Codex hooks cannot be quietly folded into the existing `claude_code_hook` channel. A verifier that did so would silently widen its trust in the chain: receipts would appear comparable across vendors when in fact each vendor's chain elides a different set of events.

## Decision

Define `codex_hook` as a **separate emission channel**, peer to `claude_code_hook`, `mcp_proxy`, `openclaw`, and `sdk` in the ADR-0010 schema split. The channel discriminator carries the trust statement: a `codex_hook` receipt means "observed via Codex's hook system, with Codex's coverage envelope," and nothing more.

### Events that emit receipts

`codex_hook` emits one receipt per Codex hook invocation that the daemon receives, for the documented covered tool surface:

- `Bash` (`PreToolUse` and `PostToolUse`)
- `apply_patch` (`PreToolUse` and `PostToolUse`)
- MCP tool calls (`PreToolUse` and `PostToolUse`)

`PreToolUse` receipts carry `decision = allowed | denied | pending`; `PostToolUse` receipts carry the tool's `output` and/or `error` and finalise `decision`. Pre/Post for the same call are linked through `session_id` plus the per-invocation correlator from Codex's hook payload, surfaced in the event body under the same `tool_use_id` field name `claude_code_hook` uses (per ADR-0013) so the daemon's pairing logic and verifier mental model stay uniform across hook-style channels. Codex's payload field name may differ from Claude Code's; the emitter normalises it to `tool_use_id`. For `apply_patch`, a `Pre`-veto blocks the patch as a whole, not individual hunks, and `decision = denied` reflects that granularity.

`WebSearch` and any shell invocation that bypasses the hooks integration (notably `unified_exec` paths) **do not** emit `codex_hook` receipts — they cannot, because no hook fires.

### Coverage gap is recorded in the receipt, not just in the ADR

The chain itself must make the blind spot machine-readable so a verifier does not have to know the contents of this ADR to interpret a chain correctly. Two parts:

1. **Channel discriminator.** `channel = "codex_hook"` is by itself a coverage statement: anyone consuming the chain can look up the channel's documented coverage envelope (this ADR) and apply the appropriate trust calculus. No `claude_code_hook` receipt can be mistaken for a `codex_hook` receipt or vice versa.
2. **Per-receipt coverage metadata.** Each `codex_hook` event carries an explicit `coverage` block in the emitter-supplied payload. The daemon canonicalises and signs this alongside the rest of the event, so the gap statement is itself attested. Schema:

   | Field | Type | Required | Allowed values |
   |-------|------|----------|----------------|
   | `covers` | array of strings | yes | closed set: `Bash`, `apply_patch`, `mcp`. Values are the literal Codex tool surface as named by Codex's hook payload, plus `mcp` as the category for any MCP tool call (whose specific identity is recorded separately in `tool.name` / `tool.server`). |
   | `excludes` | array of strings | yes | closed set: `WebSearch`, `unified_exec`. Expanded only when Codex itself adds new uncovered surfaces. |
   | `enforcement` | string | yes | one of `advisory`, `primary`. `advisory` for hook channels backed by a separate enforcement layer (Codex's sandbox); `primary` reserved for channels where the hook is itself the enforcement point. `codex_hook` always emits `advisory`; `primary` is reserved for cross-channel parity with `claude_code_hook`. |
   | `sandbox` | string | yes | one of `seatbelt` (macOS), `landlock_seccomp` (Linux), `none`. Codex on Windows reports `none`. |
   | `codex_version` | string | yes | the running Codex CLI's reported version, so a verifier can decide whether the `covers`/`excludes` claim is current for the Codex release that emitted the receipt. |

   Example: `{"covers":["Bash","apply_patch","mcp"],"excludes":["WebSearch","unified_exec"],"enforcement":"advisory","sandbox":"seatbelt","codex_version":"0.42.0"}`. RFC 8785 sorts object member names lexicographically by UTF-16 code units (per ADR-0002), so field order is irrelevant in canonicalisation; all listed fields are required.

   The `coverage` block is **emitter-asserted**, not validated against ground truth by the daemon. The daemon attests *who* sent the claim (peer credentials, binary path) and that the claim has not been tampered with after signing, but cannot independently confirm what Codex's hook integration actually does on this host. A buggy or malicious emitter could shrink `excludes` and a verifier acting on the receipt would accept fewer absences as expected. The honesty of the claim is therefore bounded by trust in the specific binary that signed it; an emitter the user did not install is a different binary in the receipts (see Trust model below).

   Verifiers MUST treat the absence of a `codex_hook` receipt for `WebSearch` or `unified_exec` activity as expected, not as evidence of suppression — and the `coverage.excludes` list is what tells them which absences are expected for this chain.

This is deliberately different from the `claude_code_hook` channel, which has its own (different) coverage envelope. Verifiers comparing chains across vendors must read the `channel` and `coverage` fields and reason per-channel; the daemon does not paper over the difference.

### Drop-counter handling

Codex hooks are short-lived, fresh-process-per-event emitters — the same property `claude_code_hook` faces. ADR-0010's in-memory drop counter (increment on `EAGAIN`, flush on the next successful event from the same emitter) does not apply, because there is no continuity across invocations: every drop is the last drop that process will ever see.

**Inherit ADR-0013's mechanism unchanged.** ADR-0013 closes this gap with a per-session drop file in the platform runtime directory (`$XDG_RUNTIME_DIR/agentreceipts/drops/<session_id>` on Linux, `$TMPDIR/agentreceipts/drops/<session_id>` on macOS, `%LOCALAPPDATA%\agentreceipts\drops\<session_id>` on Windows), guarded by an advisory lockfile, with a leave-until-success ordering that updates the file atomically via temp-file-and-rename on `EAGAIN` and unlinks it on success. The Codex emitter follows the same ordering verbatim — same paths, same lockfile semantics, same opportunistic 24-hour pruning. The daemon's `events_dropped` receipt synthesis is unchanged.

The cross-channel `drop_count` IPC field promoted by ADR-0013 (non-negative integer, optional, default 0, omitted when zero) is what carries the count from emitter to daemon. The Codex emitter is the second consumer of that field rather than the trigger for a new one — one mechanism, one IPC contract, one set of verifier expectations across both hook-style channels. The narrow residual loss window from ADR-0013 (runtime-directory wipe between hook invocations) applies identically.

### Packaging

Codex's hook integration story is thinner than Claude Code's plugins: hooks are wired up declaratively via Codex's `config.toml` rather than installed as a plugin bundle with its own manifest, lifecycle, and update channel. The agent-receipts integration matches that thinness:

- Distribute a small standalone emitter binary (`agent-receipts-codex-hook`), built per-platform and shipped through the same channel as the daemon (Homebrew, `.deb`/`.rpm`, Windows installer per ADR-0010).
- Distribute a config snippet for `config.toml` that wires `PreToolUse` and `PostToolUse` to that binary for the covered tool surface.
- The binary is a thin emitter in the ADR-0010 sense: it captures the hook's structured event, fires it over the daemon's IPC socket, and exits. No signing, no storage, no crypto — those live in the daemon.

Packaging is intentionally not a plugin bundle. Codex does not have the plugin infrastructure to make that pay off, and forcing one would mean inventing lifecycle, update, and versioning machinery that the host CLI does not provide.

### Trust model

Single-attestation layer, identical in shape to ADR-0013. The Codex emitter is invoked synchronously by Codex; Codex is the parent process. The daemon's peer-credential capture lands directly on the emitter binary, with no proxy or shim in between. An attacker who replaces `agent-receipts-codex-hook` with a different binary will be peer-attested as that different binary — receipts will record the substitute, not impersonate the legitimate emitter — and the daemon's signing keys remain unreachable from the emitter regardless of who runs it. Recording the parent identity (Codex itself, recovered from the emitter's PID via `/proc/<pid>/status`, `proc_pidinfo`, or `NtQueryInformationProcess`) in the receipt's `peer` object is a daemon-side concern shared with `claude_code_hook` and out of scope here.

This is materially different from `mcp_proxy`'s two-layer trust model: there is no proxy attesting the agent. The emitter is a child of Codex, and that is the entire chain.

## Consequences

### Positive

- Covers the Codex user base under the same chain, daemon, and verification story as Claude Code, MCP proxy, and the SDKs — receipts from a developer using both CLIs end up in one chain with monotonic `seq` and shared `session_id` grouping.
- Reuses ADR-0010's daemon, IPC transport, peer-credential capture, canonicalisation, and signing without modification. No new crypto, no new schema, no new socket. The emitter binary is small precisely because all of that is already solved.
- Inherits ADR-0013's per-session-file drop-counter mechanism and the cross-channel `drop_count` IPC field unchanged, so the verifier's mental model for hook-style channels is consistent: `events_dropped` receipts mean the same thing whether the gap originated in a Codex hook or a Claude Code hook, and the IPC envelope contract is the same single field.
- Encodes the coverage gap structurally — in the `channel` discriminator and in a signed per-receipt `coverage` block — instead of relying on out-of-band documentation. A verifier that has never read this ADR can still compute the right trust statement.
- Packaging is light: a binary plus a config snippet rather than a plugin manifest, matching what Codex actually offers.

### Negative / tradeoffs

- **Coverage is incomplete by design.** `WebSearch` and `unified_exec` activity does not appear in the chain at all from this channel. This is a property of Codex, not of agent-receipts, but the implication for users is real: a `codex_hook`-only chain is not a complete record of the agent's tool use, and we must not market it as one.
- **Verifiers must treat `codex_hook` chains differently from `claude_code_hook` chains.** The two channels have different coverage envelopes and different enforcement properties: Codex's sandbox is the primary enforcement boundary and the hook is advisory, whereas the Claude Code hook is itself the enforcement point. Anything in the verification or dashboard layer that compares vendors must read the `channel` discriminator and the per-receipt `coverage` block; it cannot treat all hook-derived receipts as equivalent.
- **Coverage claims are version-sensitive and emitter-asserted.** The `coverage.covers` / `coverage.excludes` lists describe *the running Codex's* hook integration. A future Codex release that adds `WebSearch` or completes `unified_exec` interception will widen the covered surface, and receipts emitted before and after that release will carry different (correct-at-the-time) claims. The `codex_version` field on every `coverage` block lets verifiers reason about whether a claim is current, but the daemon does not validate the claim against ground truth — see Trust model.
- **Hooks are supplementary, not primary, enforcement.** A `codex_hook` `decision = denied` receipt records that the hook said "no"; the actual stop, in most realistic scenarios, came from Seatbelt or Landlock/seccomp at the kernel layer. The receipt is honest about what it is — an observation at the hook layer — and verifiers should not infer enforcement strength from the channel alone.
- **Two channels for "the agent's CLI hooks" rather than one.** This is the right tradeoff (the channels really are different) but it is more channels for the dashboard, the docs, and any cross-channel correlation logic to know about. Adding a third hook-style channel later (some other CLI) would be straightforward — that is the point of channel separation — but the surface area grows linearly.

## Related ADRs

- [ADR-0010 (Daemon Process Separation)](./0010-daemon-process-separation.md) — defines the channel field, the daemon, the IPC transport, the peer-credential capture, and the original `events_dropped` mechanism this ADR's drop-counter handling ultimately feeds into.
- [ADR-0013 (`claude_code_hook` Emission Channel)](./0013-claude-code-hook-channel.md) — peer channel for Claude Code's hooks. This ADR inherits ADR-0013's per-session drop file, lockfile ordering, opportunistic pruning, `tool_use_id` correlator, and cross-channel `drop_count` IPC field unchanged, and deliberately diverges on coverage and packaging where Codex differs.
- [ADR-0008 (Response Hashing and Chain Completeness)](./0008-response-hashing-and-chain-completeness.md) — chain-completeness reasoning that motivates recording coverage gaps in-chain rather than only in documentation.
- [ADR-0009 (Canonicalisation Profile and VC Field Name Commitment)](./0009-canonicalization-and-schema-consistency.md) — the `coverage` block is part of the signed event body and is canonicalised under this profile.
