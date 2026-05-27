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

`2026-05-26 (end of day)` — #592 (inline publish) merged; PyPI + npm trusted publishers configured. #640 (ADR-0023 Go module path) merged; spawned #636–#639. #641 (py-readme-daemon-refresh) merged. #643 (ADR-0024 emit-failure-contract, all three SDKs) open in review. homepage-rewrite farmed — agent in flight.

---

## Decisions blocked on Otto

No decisions currently blocked.

---

## Closure groupings (logical view)

A closure is a coherent piece of work that retires a category of audit findings or installs a category of capability. Nodes group into closures; the DAG below is the dependency view.

- **`closure-0` (spec/context versioning) — SHIPPED.**
- **`closure-1` (Quick Start coherence + Go module identity) — IN PROGRESS.** ADR-0022 merged; `in-process-snippet-sweep` (#621), `spec-overview-cleanup` (#624), `go-readme-reposition` (#623), `quickstart-rewrite` (#625), `daemon-setup-stale-api` (#628), `ADR-0023-go-module-path` (#640), and `py-readme-daemon-refresh` (#641) all shipped. `homepage-rewrite` in-flight (agent dispatched 2026-05-26). ADR-0023 follow-ups (#636–#639) in-flight.
- **`closure-2` (emit failure contract) — IN PROGRESS.** `emit-failure-contract` PR #643 open in review; covers all three SDKs in one PR.
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
- state: shipped
- depends_on: []
- issues: #615 (closed)
- prs: #640 (merged)
- artifacts: `docs/adr/0023-canonical-go-module-path.md`
- notes: canonical path is `github.com/agent-receipts/ar/sdk/go`; standalone `sdk-go` gets a final deprecation release; spawned #636–#639.

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
- notes: shipped before ADR-0023 landed; import paths updated as part of ADR-0023 follow-ups (#636).

#### `spec-overview-cleanup`
- state: shipped
- depends_on: [`spec-v0.4.0-publish`]
- conflicts_with: []
- issues: #620
- prs: #624 (merged)
- artifacts: `site/src/content/docs/specification/overview.mdx` bumped to v0.4.0; "Relationship to existing work" reorganized into normative ancestry vs adjacent projects.

#### `homepage-rewrite`
- state: in-flight (agent dispatched)
- depends_on: [`quickstart-rewrite`]
- farmable: yes (with Otto's final pass on opening paragraph)
- notes: agent dispatched 2026-05-26; will leave `{/* OTTO: personal twist */}` placeholder on opening paragraph. Brief: lead with failure scenario, drop "no project does this" framing, add `/ecosystem/landscape/` link. No PR yet.

#### `daemon-setup-stale-api`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: []
- issues: #627
- prs: #628 (merged)
- artifacts: `site/src/content/docs/getting-started/daemon-setup.mdx` — TS `Emitter` → `DaemonEmitter`, dropped `@alpha` install tag, Go `emitter.New` → `emitter.NewDaemon`, macOS socket path now `$XDG_DATA_HOME/agent-receipts/events.sock`.
- notes: surfaced by an agent while doing #625; the macOS socket-path fix was the user-impacting bit (readers were landing on the wrong socket and the handshake failed silently).

#### `py-readme-daemon-refresh`
- state: shipped
- depends_on: [`ADR-0022-deployment-shape`]
- conflicts_with: []
- issues: #630 (closed)
- prs: #641 (merged)
- artifacts: `sdk/py/README.md` — daemon-mediated path leads, `DaemonEmitter`/`HttpEmitter`/`WalEmitter` documented, `ActionInput` re-exported from top-level, stale links fixed.
- notes: bundled five paper-cuts from the v0.10.0 first-run audit.

#### `inline-publish-pypi-npm`
- state: shipped
- depends_on: []
- prs: #592 (merged)
- notes: PyPI trusted publisher updated to `release-sdk-py.yml`; npm trusted publisher updated to `release-sdk-ts.yml`. Release pipeline now fully wired.

---

### Closure 1 — ADR-0023 follow-ups

#### `go-import-path-sweep`
- state: in-flight
- depends_on: [`ADR-0023-go-module-path`]
- issues: #636
- farmable: yes
- notes: update all import paths from `sdk-go/...` to `ar/sdk/go/...`

#### `sdk-go-deprecation-release`
- state: in-flight
- depends_on: [`ADR-0023-go-module-path`]
- issues: #637
- farmable: yes
- notes: publish final deprecation release on `github.com/agent-receipts/sdk-go`

#### `collector-tagging`
- state: in-flight
- depends_on: [`ADR-0023-go-module-path`]
- issues: #638
- farmable: yes
- notes: tag collector module independently; verify `go install ...collector@latest`

#### `d5-release-verification`
- state: in-flight
- depends_on: [`go-import-path-sweep`, `collector-tagging`]
- issues: #639
- farmable: yes
- notes: run D5 release-time verification

---

### Closure 2 — emit failure contract

#### `emit-failure-contract`
- state: in-flight
- depends_on: []
- issues: #599
- prs: #643 (open, in review)
- farmable: no (PR in review; has merge conflict — other agent rebasing)
- notes: implements ADR-0024; covers all three SDKs in one PR: Go `WithBestEffort()`, Python `best_effort=True`, TS `bestEffort: true`. Shared conformance vector at `cross-sdk-tests/emit_failure_vectors.json`. Closes #599.

#### `py-protocol-arity-fix` (PY-P4)
- state: shipped (superseded by #643)
- depends_on: [`emit-failure-contract`]
- conflicts_with: []
- notes: covered by #643.

#### `py-silent-drop-fix` (PY-P9)
- state: shipped (superseded by #643)
- depends_on: [`emit-failure-contract`, `py-protocol-arity-fix`]
- notes: covered by #643.

#### `go-silent-drop-fix` (GO-P5)
- state: shipped (superseded by #643)
- depends_on: [`emit-failure-contract`]
- notes: covered by #643.

#### `ts-silent-drop-verify-and-fix`
- state: shipped (superseded by #643)
- depends_on: [`emit-failure-contract`]
- notes: covered by #643.

---

### Verification contract (deferred)

#### `ADR-0025-verification-contract`
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

As of `2026-05-26 (end of day)`:

Nothing is immediately farmable — everything is in-flight or in review:

- `emit-failure-contract` → #643 open in review (merge conflict; other agent rebasing).
- `go-import-path-sweep` (#636), `sdk-go-deprecation-release` (#637), `collector-tagging` (#638), `d5-release-verification` (#639) — agents in flight.
- `homepage-rewrite` — agent in flight; Otto owes a final pass on the opening paragraph once the PR lands.

Otto owes:
- Final pass on `homepage-rewrite` opening paragraph once PR lands (placeholder `{/* OTTO: personal twist */}` will be left by the agent).

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
