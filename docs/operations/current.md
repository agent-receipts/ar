# OPERATIONS.md — Active work graph

> **Purpose.** This file is the operational source of truth for what is in flight, what is blocked, and what is next. Updated whenever a node's state changes. Read by humans and by agents.
>
> **Scope.** Captures the *active subgraph* of work: the audit response, the v1-blocker chain, and current foreground work. Does not capture every open issue — most open issues are background, not blocking the current focus. Items enter this file when they become active; they leave it when they ship.
>
> **Schema.** Each node has: `state`, `depends_on`, `conflicts_with`, `issues` / `prs`, `farmable`, `notes`. Conflicts mean "may touch overlapping files / state; sequence rather than parallelize."

---

## How to use this file

**Otto:** Open this first when starting a session. Scan `## Decisions blocked on Otto` first — those are foreground. Then scan `## Next farmable (computed)` — those are what can be dispatched to agents right now.

**Agent (Claude Code driver session):** Read this file. Compute the set of nodes where `state: open` AND all `depends_on` are `shipped` AND no node in `conflicts_with` is currently `in-flight`. From that set, surface to Otto any `blocked on otto` items first. If none, pick the node with the most dependents (clears the most downstream work). Execute the prompt referenced in its issue. On completion, update this file: set `state: shipped`, record the merged PR.

**Agent (subagent doing one node's work):** Read this file for context, but do not modify it. Your scope is one node's issue.

---

## Last updated

`2026-05-29` — #643 (emit-failure-contract / ADR-0025) merged, closing closure-2; #664 (Gate #2 release round-trip) merged, closes #651; #666 (Gate #1 execute mode for README snippets) merged, closes #650; #667 (Gate #5 MDX snippet execution) merged, closes #652; issue #599 closed manually; `collector-tagging` (#638) farmed off. Background sweep farmed off 7 additional items: #476, #473, #488, #462, #495, #622, #629 (all in-flight).

> **ADR numbering note.** The numbers settled after three landed in close succession: **ADR-0023** = canonical Go module path (#640/#642), **ADR-0024** = project verification contract (#658), **ADR-0025** = emit failure contract (#643, merged). Earlier snapshots had 0024/0025 swapped.

---

## Decisions blocked on Otto

No decisions currently blocked. (`homepage-rewrite` shipped via #644 — if the agent left an `{/* OTTO: personal twist */}` placeholder in the opening paragraph, that final copy pass is the only outstanding Otto touch, and it is non-blocking.)

---

## Closure groupings (logical view)

A closure is a coherent piece of work that retires a category of audit findings or installs a category of capability. Nodes group into closures; the DAG below is the dependency view.

- **`closure-0` (spec/context versioning) — SHIPPED.**
- **`closure-1` (Quick Start coherence + Go module identity) — ESSENTIALLY COMPLETE.** All Quick Start / README / ADR nodes shipped, including `homepage-rewrite` (#644) and `ADR-0023-go-module-path` (#640). Two ADR-0023 follow-ups remain in-flight: `collector-tagging` (#638) and `d5-release-verification` (#639, blocked on #638). Once both close, closure-1 (and its tracker #598) can close.
- **`closure-2` (emit failure contract) — SHIPPED.** ADR-0025 implemented across all three SDKs (#643, merged 2026-05-28). Issue #599 closed.
- **`verification-contract` (ADR-0024) — SHIPPED & BUILDING GATES.** ADR-0024 landed (#658). Gate #1 type-check shipped (#632); Gate #1 execute mode shipped (#666, closes #650). Gate #2 (release round-trip) shipped (#664, closes #651). Gate #5 (MDX snippet execution) shipped (#667, closes #652). Gates #3/#4/#6/#7 are future siblings.
- **`v1-blockers`** (orthogonal to closures; tracked by `v1-blocker` label) — #534 (AWS KMS signers) shipped for TS + Python (#663); #535 (ephemeral-compute deployment guide) shipped (#660). Foreground for the v1 release path; not part of the audit response.
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
- notes: shipped before ADR-0023 landed; import paths updated as part of ADR-0023 follow-up #636.

#### `spec-overview-cleanup`
- state: shipped
- depends_on: [`spec-v0.4.0-publish`]
- conflicts_with: []
- issues: #620
- prs: #624 (merged)
- artifacts: `site/src/content/docs/specification/overview.mdx` bumped to v0.4.0; "Relationship to existing work" reorganized into normative ancestry vs adjacent projects.

#### `homepage-rewrite`
- state: shipped
- depends_on: [`quickstart-rewrite`]
- prs: #644 (merged)
- artifacts: `site/src/content/docs/index.mdx` — leads with failure scenario, drops "no project does this" framing, links `/ecosystem/landscape/`.
- notes: agent-drafted then merged. If a `{/* OTTO: personal twist */}` placeholder was left in the opening paragraph, Otto owes a final copy pass — non-blocking.

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
- notes: bundled five paper-cuts from the v0.10.0 first-run audit (closed PR #591). Regression tests salvaged separately into `sdk/py/tests/contracts/` (#633).

#### `inline-publish-pypi-npm`
- state: shipped
- depends_on: []
- prs: #592 (merged)
- notes: PyPI trusted publisher updated to `release-sdk-py.yml`; npm trusted publisher updated to `release-sdk-ts.yml`. Release pipeline now fully wired.

---

### Closure 1 — ADR-0023 follow-ups

#### `go-import-path-sweep`
- state: shipped
- depends_on: [`ADR-0023-go-module-path`]
- issues: #636 (closed)
- notes: all README/example import paths updated `sdk-go/...` → `ar/sdk/go/...`.

#### `sdk-go-deprecation-release`
- state: shipped
- depends_on: [`ADR-0023-go-module-path`]
- issues: #637
- prs: #645 (merged)
- notes: final deprecation release staged for the standalone `github.com/agent-receipts/sdk-go` module.

#### `collector-tagging`
- state: in-flight
- depends_on: [`ADR-0023-go-module-path`]
- issues: #638 (open)
- prs: #648 (merged — release automation only)
- farmable: yes (farmed off 2026-05-29)
- notes: #648 landed the GoReleaser config + `collector/v*` release workflow. Still open in #638: actually push the `collector/v0.13.0` tag aligned to `sdk/go/v0.13.x` and verify `go install github.com/agent-receipts/ar/collector/cmd/collector@latest` builds against a fresh GOPATH.

#### `d5-release-verification`
- state: blocked
- depends_on: [`go-import-path-sweep`, `collector-tagging`]
- issues: #639 (open)
- farmable: no (blocked on `collector-tagging` #638 closing)
- notes: run ADR-0023 D5 one-time verification — `go get @latest` resolves, collector `go install` builds, README hello-world compiles — and record results in #639.

---

### Closure 2 — emit failure contract (ADR-0025)

#### `emit-failure-contract`
- state: shipped
- depends_on: []
- issues: #599 (closed)
- prs: #643 (merged)
- artifacts: `docs/adr/0025-emit-failure-contract.md`; `cross-sdk-tests/emit_failure_vectors.json`
- notes: implements ADR-0025 (renumbered from 0023→0024→0025 as other ADRs landed). Emit MUST surface transport failure by default; best-effort is opt-out (Go `WithBestEffort()`, Python `best_effort=True`, TS `bestEffort: true`). Breaking change across all three SDKs.

#### `py-protocol-arity-fix` (PY-P4)
- state: decoupled from this closure
- depends_on: []
- notes: per #643, no longer a blocking prerequisite — the base obligation is "surface the failure"; durability (WAL wrapping) is opt-in. PY-P4 moves to ADR-0020 step-2 work (daemon ingesting signed receipts). The salvaged contract test `test_wal_emitter_cannot_wrap_daemon_emitter` (#633) still pins the current footgun and should flip to a positive assertion when PY-P4 lands.

#### `py-silent-drop-fix` (PY-P9) / `go-silent-drop-fix` (GO-P5) / `ts-silent-drop-verify-and-fix`
- state: superseded by #643
- depends_on: [`emit-failure-contract`]
- notes: all three SDK silent-drop fixes are covered by the single #643 PR.

---

### Verification contract (ADR-0024 — shipped, building gates)

#### `ADR-0024-verification-contract`
- state: shipped
- depends_on: []
- issues: #600 (closed)
- prs: #658 (merged)
- artifacts: `docs/adr/0024-project-verification-contract.md`
- notes: was deferred; landed once Closures 1 and 2 demonstrated the property-with-gate pattern. Defines a gate catalogue (Gates #1–#7).

#### `cnap-snippet-ci` (Gate #1 — type-check)
- state: shipped
- depends_on: []
- issues: #595 (closed)
- prs: #632 (merged)
- artifacts: `scripts/readme_snippets/` harness; `readme-snippets.yml` CI gate; in-tree + published snippet checks for Go/TS/Python
- notes: README code-snippet CI gate — type-check half of Gate #1 of ADR-0024. Also fixed a stale module path in `sdk/go/README.md` and a wrong `ActionInput` call in the root README Python quick-start.

#### `readme-snippet-execution` (Gate #1 — execute)
- state: shipped
- depends_on: [`cnap-snippet-ci`]
- issues: #650 (closed)
- prs: #666 (merged)
- artifacts: `--mode run` added to `scripts/readme_snippets/check.py`; `Run … snippets (in-tree)` CI step for all three SDKs
- notes: adds the execute half of Gate #1 — snippets actually run in an isolated tmpdir, not just type-checked. Non-hermetic snippets (`DaemonEmitter`, `KMSSigner`, etc.) marked `no-run` with documented reason; still covered by type-check gate.

#### `mdx-snippet-execution` (Gate #5)
- state: shipped
- depends_on: [`readme-snippet-execution`]
- issues: #652 (closed)
- prs: #667 (merged)
- artifacts: `mdx-snippets.yml` CI gate; MDX JSX comment directives in `extract.py`
- notes: executes runnable SDK snippets in site `.mdx` docs against in-tree SDK. Reuses gate #1 run-mode harness. Type-check gate for MDX deferred (12 pre-existing doc type-strictness issues; doc-quality follow-up, not a regression).

#### `release-roundtrip-verification` (Gate #2)
- state: shipped
- depends_on: [`ADR-0024-verification-contract`]
- issues: #651 (closed)
- prs: #664 (merged)
- artifacts: `scripts/release_verify/check.py` + 23 unit tests; `release-verify` job wired into `release-sdk-{go,py,ts}.yml`
- notes: post-publish CI step per SDK — fetch the just-published artifact from the public registry in a clean env, assert resolved version == released version. Release-blocking.

---

### Activated 2026-05-29 — background items now in-flight

#### `production-key-guard` (#476)
- state: in-flight (farmed)
- depends_on: []
- issues: #476 (open)
- farmable: yes
- notes: throw `ProductionKeyProviderError` when `AGENTRECEIPTS_PRODUCTION=true`, loud warning otherwise. Fully spec'd in ADR-0019 §S2. All three SDKs.

#### `ts-hpke-hand-roll` (#473)
- state: in-flight (farmed)
- depends_on: []
- issues: #473 (open)
- farmable: yes
- notes: replace `@hpke/core` with hand-rolled HPKE from `node:crypto`. RFC 9180 §7.1.3 DeriveKeyPair gotcha documented; existing test vectors to pin against. TS SDK only. 0.9.0 stable still ships `@hpke/core` lazy-loaded; this is the tracked removal.

#### `sequential-emit-under-parallel` (#488)
- state: in-flight (farmed)
- depends_on: []
- issues: #488 (open)
- farmable: yes
- notes: queue serialisation inside SDK + warning on concurrent `emit()` calls. Clear spec. All three SDKs.

#### `env-marker-secondary-host` (#462)
- state: in-flight (farmed)
- depends_on: []
- issues: #462 (open)
- farmable: yes
- notes: env-var-driven secondary host detection in mcp-proxy. Env var table and fallback logic fully specified; it's a TODO in `detect_linux.go`.

#### `editor-integration-guides` (#495)
- state: in-flight (farmed)
- depends_on: []
- issues: #495 (open)
- farmable: yes
- notes: MCP proxy integration guides for Cursor, Windsurf, VS Code Copilot, JetBrains, Cline. Pure docs work using the Claude Code guide as template.

#### `aivs-cg-landscape` (#622)
- state: in-flight (farmed)
- depends_on: []
- issues: #622 (open)
- farmable: yes
- notes: add W3C AIVS Community Group entry to `landscape.mdx`. Content and suggested framing given in the issue.

#### `codeql-advanced-setup` (#629)
- state: in-flight (farmed)
- depends_on: []
- issues: #629 (open)
- farmable: yes
- notes: migrate CodeQL from default to advanced setup with `paths-ignore` for docs-only PRs. CI workflow change — goes through a PR per convention.

---

## Background — not in the active graph but worth noting

- **`v1-blocker` work:** #534 (AWS KMS signers) shipped for TS + Python (#663) — confirm whether Go KMS coverage is in scope/remaining. #535 (ephemeral-compute deployment guide) shipped (#660).
- **Operator tooling — SHIPPED:** #539 `agent-receipts doctor` (#661), #540 `verify-event` (#659), #552 `agent-receipts show <seq>` (#662). Outgrowth of the Max-forged-a-receipt incident.
- **Standards/positioning:** #555 (v0.3.0 blog post), #556/#557/#558 (AIVS CG contributions), #559 (draft-sharif review comment), #561 (ADR on adjacent format posture). Cadence-driven, not blocker-driven.
- **Blog campaign (Posts 3–7):** #541, #542, #543, #544 + draft PRs #442/#444 — contingent on Otto having writing time.
- **Idle PRs:** #532 (hermes-agent plugin) — open since 2026-05-22, needs a review pass or a close decision.
- **Daemon redesign:** the v2 work. Not surfaced as issues at the granularity that would let it enter this DAG; Otto's foreground design work.

---

## Next farmable (computed)

As of `2026-05-29`, applying the "open + dependencies-met + no in-flight conflicts" rule:

All currently farmable nodes have been dispatched. In-flight:

- `collector-tagging` (#638) — tag push + go install verify; unblocks `d5-release-verification` (#639)
- `production-key-guard` (#476) — production guard across all 3 SDKs
- `ts-hpke-hand-roll` (#473) — replace `@hpke/core` in TS SDK
- `sequential-emit-under-parallel` (#488) — serialised emit under concurrent calls, all 3 SDKs
- `env-marker-secondary-host` (#462) — mcp-proxy secondary host detection
- `editor-integration-guides` (#495) — editor integration docs
- `aivs-cg-landscape` (#622) — landscape.mdx W3C AIVS CG entry
- `codeql-advanced-setup` (#629) — CodeQL advanced config with paths-ignore

Unlocks when `collector-tagging` closes:
- **`d5-release-verification` (#639)**

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
