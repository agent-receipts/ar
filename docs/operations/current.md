# OPERATIONS.md — Active work graph

> **Purpose.** This file is the operational source of truth for what is in flight, what is blocked, and what is next. Updated whenever a node's state changes. Read by humans and by agents.
>
> **Scope.** Captures the *active subgraph* of work: the audit response, the v1-blocker chain, and current foreground work. Does not capture every open issue — the project has 77 of those and most are background, not blocking the current focus. Items enter this file when they become active; they leave it when they ship.
>
> **Schema.** Each node has: `state`, `depends_on`, `conflicts_with`, `issues` / `prs`, `farmable`, `notes`. Conflicts mean "may touch overlapping files / state; sequence rather than parallelize."

---

## How to use this file

**Otto:** Open this first when starting a session. Scan `## Decisions blocked on Otto` first — those are foreground. Then scan `## Next farmable (computed)` — those are what can be dispatched to agents right now.

**Agent (Claude Code driver session):** Read this file. Compute the set of nodes where `state: open` AND all `depends_on` are `shipped` AND no node in `conflicts_with` is currently `in-flight`. From that set, surface to Otto any `blocked on otto` items first. If none, pick the node with the most dependents (clears the most downstream work). Execute the prompt referenced in its issue. On completion, update this file: set `state: shipped`, record the merged PR.

**Agent (subagent doing one node's work):** Read this file for context, but do not modify it. Your scope is one node's issue.

---

## Last updated

`2026-05-26` — #632 (`cnap-snippet-ci` / #595) merged. #633 (py contract tests salvaged from #591) merged — 7 tests in `sdk/py/tests/contracts/`, two flagged for flip when `emit-failure-contract` (#599) lands. `spec-publishing-tag-aware` (#612) PR open as #634 — awaiting review.

---

## Decisions blocked on Otto

- **`emit-failure-contract`** (gates Closure 2) — decide that emit MUST surface transport failure as raised error / non-nil return; durability across crashes is opt-in via WAL; silent drop is never the default. Once recorded, per-SDK propagation is farmable. Issue: #599.
- **`homepage-rewrite`** — needs Otto's voice; cannot farm. Should lead with a concrete failure scenario, drop crypto-jargon-first opening, retract any residual "no project does this" framing, add comparison link to `/ecosystem/landscape/`. No issue filed yet.
- **`#615 ADR-0023 (Go module path)`** — needs the ADR drafted (issue exists; no PR yet). #623 already merged, so if the ADR ships with a Go module path change, `sdk/go/README.md` will need a follow-up rebase to update import paths.
- **`#600 verification-contract ADR`** — decide whether to land now (commits the project to property-with-gate as policy) or defer until Closures 1 and 2 demonstrate the pattern. Synthesis recommends defer.
- **`#592 inline-publish-pypi-npm`** — PR is technically sound and CI is green, but PyPI and npm "trusted publishing" authorizes a *specific* workflow filename. The new inline publish steps in `release-sdk-py.yml` / `release-sdk-ts.yml` will be rejected at release time until trusted-publisher configs are updated. Manual step: add `release-sdk-py.yml` to https://pypi.org/manage/project/agent-receipts/settings/publishing/ and add `release-sdk-ts.yml` to the npm package's trusted-publisher list. Keep the old entries so the manual escape hatches still work. Then merge #592. Release-blocker — every release ships silently broken until this lands.

---

## Closure groupings (logical view)

A closure is a coherent piece of work that retires a category of audit findings or installs a category of capability. Nodes group into closures; the DAG below is the dependency view.

- **`closure-0` (spec/context versioning) — SHIPPED** except `spec-publishing-tag-aware` (#612).
- **`closure-1` (Quick Start coherence + Go module identity) — IN PROGRESS.** ADR-0022 merged; `in-process-snippet-sweep` (#621), `spec-overview-cleanup` (#624), `go-readme-reposition` (#623), `quickstart-rewrite` (#625), and `daemon-setup-stale-api` (#628 closing #627) all shipped. Remaining: `ADR-0023-go-module-path` (#615 — needs ADR drafted by Otto), `homepage-rewrite` (blocked on Otto's voice), and `py-readme-daemon-refresh` (#630 — farmable; bundles five v0.10.0 first-run audit paper-cuts).
- **`closure-2` (emit failure contract) — BLOCKED ON OTTO DECISION.** No work farmable until contract decided.
- **`verification-contract` (#600) — DEFERRED** by recommendation; revisit after Closure 1 and 2 demonstrate the pattern.
- **`v1-blockers`** (orthogonal to closures; tracked by `v1-blocker` label) — includes #534 (Cloud KMS signers), #535 (ephemeral-compute deployment guide). Foreground for the v1 release path; not part of audit response. Listed here so the file acknowledges they exist; details in their own issues.
- **`daemon-v2`** — Otto's foreground design work. Not yet broken into nodes here; add when it becomes farmable.

---

## Active nodes (DAG)

### Closure 0 — spec/context versioning

#### `ADR-0021-spec-versioning`
- state: shipped
- depends_on: []
- issues: #597 (closed)
- prs: #601 (merged)
- artifacts: `docs/adr/0021-spec-and-context-versioning.md`

#### `spec-v0.4.0-publish`
- state: shipped
- depends_on: [`ADR-0021-spec-versioning`]
- prs: #610 (merged)
- artifacts: live at `https://agentreceipts.ai/spec/v0.4.0/`
- notes: tag `spec-v0.4.0` pushed and verified

#### `context-v1-author`
- state: shipped
- depends_on: [`ADR-0021-spec-versioning`]
- prs: #611 (merged)
- artifacts: live at `https://agentreceipts.ai/context/v1`
- notes: covers terms across receipts produced under v0.1.0–v0.4.0 plus `keyRotation` extension; closes the load-bearing correctness gap (every receipt's `@context` URL now resolves)

#### `spec-publishing-tag-aware`
- state: shipped
- depends_on: [`spec-v0.4.0-publish`]
- conflicts_with: []
- issues: #612 (closed)
- prs: #634 (merged)
- artifacts: `scripts/sync-spec.mjs` tag-aware; `site.yml` triggers on `spec-v*` tag push; cross-references pinned to `blob/spec-vX.Y.Z/`
- notes: closes the tag-vs-merge gap and the link-drift gap that Copilot surfaced on #610.

---

### Closure 1 — Quick Start coherence + Go module identity

#### `ADR-0022-deployment-shape`
- state: shipped
- depends_on: []
- issues: #614 (closed)
- prs: #619 (merged)
- artifacts: `docs/adr/0022-canonical-deployment-shape.md`
- notes: daemon-mediated is canonical, in-process is tutorial-only with mandatory "Not for production" note, no runtime enforcement (deferred)

#### `ADR-0023-go-module-path`
- state: open (needs ADR drafted)
- depends_on: []
- conflicts_with: [`go-readme-reposition`] (soft — repositioning under unresolved canonical path risks re-edit if path decision flips)
- issues: #615 (tracker — no PR yet)
- farmable: no (Otto drafts the ADR PR)
- notes: proposed direction is monorepo `github.com/agent-receipts/ar/sdk/go` canonical; standalone `sdk-go` gets a final deprecation release

#### `quickstart-rewrite`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`, `spec-v0.4.0-publish`]
- conflicts_with: [`in-process-snippet-sweep`] (both may touch `sdk/py/README.md`; resolved — #621 shipped first)
- issues: #616
- prs: #625 (merged)
- artifacts: `site/src/content/docs/getting-started/quick-start.mdx` rewritten — Python/TS/Go each follow Install → daemon → emit → `agent-receipts verify`; in-process demoted to "tutorial and testing only" appendix with ADR-0022 D2 "Not for production" `:::danger` note.
- notes: surfaced #627 (daemon-setup.mdx had stale APIs and socket path); fixed as #628.

#### `in-process-snippet-sweep`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: [`quickstart-rewrite`, `go-readme-reposition`]
- issues: #617
- prs: #621 (merged)
- artifacts: D2 "Not for production" note across SDK READMEs and site `.mdx` quick-start sections
- notes: merged first of the three overlapping PRs; resolved file overlap with #623 and #625 by going first.

#### `go-readme-reposition`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: [`in-process-snippet-sweep` (resolved — #621 shipped first), `ADR-0023-go-module-path`]
- issues: #618
- prs: #623 (merged)
- artifacts: `sdk/go/README.md` leads with daemon path; collector positioned under "Enterprise / multi-host."
- notes: shipped before ADR-0023 landed; if the ADR lands with a Go module path change, this README will need a follow-up rebase to update import paths.

#### `spec-overview-cleanup`
- state: shipped
- depends_on: [`spec-v0.4.0-publish`]
- conflicts_with: []
- issues: #620
- prs: #624 (merged)
- artifacts: `site/src/content/docs/specification/overview.mdx` bumped to v0.4.0; "Relationship to existing work" reorganized into normative ancestry vs adjacent projects.

#### `homepage-rewrite`
- state: blocked on otto writing
- depends_on: [`quickstart-rewrite`] (so the homepage CTA can link into a coherent Quick Start)
- issues: none yet — file when Otto starts
- farmable: no — needs Otto's voice

#### `daemon-setup-stale-api`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: []
- issues: #627
- prs: #628 (merged)
- artifacts: `site/src/content/docs/getting-started/daemon-setup.mdx` — TS `Emitter` → `DaemonEmitter`, dropped `@alpha` install tag, Go `emitter.New` → `emitter.NewDaemon`, macOS socket path now `$XDG_DATA_HOME/agent-receipts/events.sock`.
- notes: surfaced by an agent while doing #625; the macOS socket-path fix was the user-impacting bit (readers were landing on the wrong socket and the handshake failed silently).

#### `py-readme-daemon-refresh`
- state: open
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: []
- issues: #630
- farmable: yes
- notes: bundles five paper-cuts from the v0.10.0 first-run audit (closed PR #591). Lead `sdk/py/README.md` with daemon-mediated signing per ADR-0022 (matches what #625 did for the site); document `DaemonEmitter` + the new `agent_receipts.emitters` package (`HttpEmitter`, `WalEmitter`, `CompositeEmitter`); reference `agent-receipts verify` as the confirmation path; re-export `ActionInput` from the top-level package; fix stale `agent-receipts/sdk-py` badge/links. Closure-1 follow-on, analogous to how `daemon-setup-stale-api` (#628) closed `daemon-setup.mdx` gaps mid-closure.

---

### Closure 2 — emit failure contract

#### `emit-failure-contract`
- state: blocked on otto decision
- depends_on: []
- issues: #599
- farmable: no (decision first)
- notes: proposed wording in #599. Per-SDK propagation issues are not filed yet; they get filed once the contract is recorded.

#### `py-protocol-arity-fix` (PY-P4)
- state: not yet filed as issue
- depends_on: [`emit-failure-contract`]
- conflicts_with: []
- farmable: yes once filed and contract decided
- notes: prerequisite for Py silent-drop fix; the Protocol shape must capture `DaemonEmitter.emit`'s real arity so `WalEmitter` can wrap it.

#### `py-silent-drop-fix` (PY-P9)
- state: not yet filed as issue
- depends_on: [`emit-failure-contract`, `py-protocol-arity-fix`]
- farmable: yes once predecessors complete

#### `go-silent-drop-fix` (GO-P5)
- state: not yet filed as issue
- depends_on: [`emit-failure-contract`]
- farmable: yes once contract decided

#### `ts-silent-drop-verify-and-fix`
- state: not yet filed as issue
- depends_on: [`emit-failure-contract`]
- farmable: yes once contract decided
- notes: TS audit did not measure emit-without-daemon behavior; first step is a one-line test confirming the suspected silent drop, then fix.

---

### Verification contract (deferred)

#### `ADR-0024-verification-contract`
- state: deferred
- depends_on: [`closure-1-complete`, `closure-2-complete`]
- issues: #600
- notes: lands after Closures 1 and 2 demonstrate the pattern; revisit when those ship.

#### `cnap-snippet-ci` (closes #595, instance of verification contract)
- state: shipped
- depends_on: [] (can ship independently of #600)
- issues: #595 (closed)
- prs: #632 (merged)
- artifacts: `scripts/readme_snippets/` harness; `readme-snippets.yml` CI gate; in-tree + published snippet checks for Go/TS/Python
- notes: README code-snippet CI gate — predates this OPERATIONS.md framing but is exactly the first gate the verification-contract ADR would mandate. Also fixed stale module path in `sdk/go/README.md` and a wrong `ActionInput` call in root README Python quick-start.

---

## Background — not in the active graph but worth noting

These exist as open issues; they are foreground for *some* future session but not blocking current work. Listed so the file acknowledges them; details in the issues themselves.

- **`v1-blocker` work:** #534 (Cloud KMS signers), #535 (ephemeral compute deployment guide). The label suggests these gate the v1 release; they are not part of the audit response.
- **Standards/positioning:** #555 (v0.3.0 blog post), #556/#557/#558 (AIVS CG contributions), #559 (draft-sharif review comment), #561 (ADR on adjacent format posture). These are the standards-room presence work; cadence-driven, not blocker-driven.
- **Blog campaign (Posts 3–7):** #541, #542, #543, #544 — drafted as issue bodies, contingent on Otto having writing time.
- **Operator tooling:** #539 (`agent-receipts doctor`), #540 (`verify-event`), #552 (`agent-receipts show <seq>`) — outgrowth of the Max-forged-a-receipt incident; ship when the hardening surface is being touched anyway.
- **Daemon redesign:** the v2 work. Not surfaced as issues at the granularity that would let it enter this DAG; Otto's foreground design work.

---

## Next farmable (computed)

As of `2026-05-26` (post-merge of #632 and #633):

1. **`py-readme-daemon-refresh` (#630)** — independent; touches `sdk/py/README.md` only; no overlap with open PRs or active worktrees. Dispatchable now.

In-flight (not farmable but not blocked either):

- `spec-publishing-tag-aware` → #634 open — needs review before merge.

Decisions Otto owes (each one unblocks downstream farmable work):

- `emit-failure-contract` (#599) — recording the contract unblocks 4 SDK nodes (`py-protocol-arity-fix`, `py-silent-drop-fix`, `go-silent-drop-fix`, `ts-silent-drop-verify-and-fix`).
- `ADR-0023-go-module-path` (#615) — needs the ADR written. If it lands with a Go module path change, the just-shipped `go-readme-reposition` work will need a follow-up rebase to update import paths.
- `homepage-rewrite` — needs Otto's voice; unblocks the broader new-visitor sweep.

---

## Update protocol

When a node ships:
1. Find the node block in this file.
2. Change `state: open` → `state: shipped`.
3. Add the merged PR number under `prs:`.
4. Add `artifacts:` if the work produced a durable URL or file.
5. Recompute the "Next farmable" section. (Move newly-unblocked nodes up if needed.)

When a decision is made:
1. Move the item out of `## Decisions blocked on Otto`.
2. If it was `farmable: no`, change it to `farmable: yes` and add the prompt reference.
3. File any implementation issues spawned by the decision; add them as new nodes.

When a new issue is filed that's part of an active closure:
1. Add it as a new node with full schema.
2. Wire up `depends_on` / `conflicts_with`.
3. Add to "Next farmable" if it qualifies.

When an issue closes that *isn't* in this file (background work):
1. No action. The file tracks active work, not all activity.

---

## Conventions

- A node's `issues` and `prs` are for cross-reference; the issues themselves remain the source of truth for *task* detail. This file is the source of truth for *graph* state.
- `conflicts_with` is for shared mutable state (same file, same config), not for logical coupling. Two unrelated docs touching different files don't conflict even if they cover related topics.
- `farmable: yes` means an agent can execute this node without Otto's involvement except to review the PR. `farmable: no` means Otto must do part of the work (writing, deciding) before the rest can run.
- A "closure" is editorial. Nodes don't need to belong to one; the closure groupings are how Otto thinks about the work, not how the DAG enforces it.
