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

`2026-06-08` — PR #753 merged: Layer 2 subagent chain delegation. Hook forwards `agent_id`; daemon routes to per-agent chains keyed `<rootChainID>/agent/<agentID>`; first receipt on each chain carries `delegation.parent_chain_id` + `delegation.parent_receipt_id` + `delegation.delegator.id`. No release cut yet — alpha is the next step when ready.

`2026-06-03` — #655 (`daemon-sdk-protocol-compat-gate`, Gate #8) shipped; closed 2026-06-03. #656 (`sbom-deps-match-gate`) found already closed 2026-06-01; marked shipped. **Active DAG fully clear** — no farmable nodes remain. Foreground shifts to `daemon-v2` design work (not yet broken into nodes).

> **ADR numbering note.** The numbers settled after three landed in close succession: **ADR-0023** = canonical Go module path (#640/#642), **ADR-0024** = project verification contract (#658), **ADR-0025** = emit failure contract (#643, merged). Earlier snapshots had 0024/0025 swapped.

---

## Decisions blocked on Otto

No decisions currently blocked. (`homepage-rewrite` shipped via #644 — if the agent left an `{/* OTTO: personal twist */}` placeholder in the opening paragraph, that final copy pass is the only outstanding Otto touch, and it is non-blocking.)

---

## Closure groupings (logical view)

A closure is a coherent piece of work that retires a category of audit findings or installs a category of capability. Nodes group into closures; the DAG below is the dependency view.

- **`closure-0` (spec/context versioning) — SHIPPED.**
- **`closure-1` (Quick Start coherence + Go module identity) — COMPLETE.** All Quick Start / README / ADR nodes shipped, including `homepage-rewrite` (#644) and `ADR-0023-go-module-path` (#640). ADR-0023 follow-ups `collector-tagging` (#638) and `d5-release-verification` (#639) both closed 2026-05-30. Tracker #598 can now close.
- **`closure-2` (emit failure contract) — SHIPPED.** ADR-0025 implemented across all three SDKs (#643, merged 2026-05-28). Issue #599 closed.
- **`verification-contract` (ADR-0024) — ALL GATES SHIPPED.** ADR-0024 landed (#658). Gate #1 type-check shipped (#632); Gate #1 execute mode shipped (#666, closes #650). Gate #2 (release round-trip) shipped (#664, closes #651). Gate #5 (MDX snippet execution) shipped (#667, closes #652). Gate #6 (schema-conformance) shipped (#696, closes #653). Gate #7 (byte-identity) shipped (#698, closes #654). Gate #8 (daemon ↔ SDK protocol compatibility) shipped (#705, closes #655). Gate #10 (dependency-manifest/SBOM) shipped (#699, closes #656). Gates #3/#4/#9 tracked under ADR-0021 (#597).
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
- state: shipped
- depends_on: [`ADR-0023-go-module-path`]
- issues: #638 (closed)
- prs: #648 (merged — release automation); `collector/v0.13.0` tag pushed and verified
- notes: GoReleaser config + release workflow in #648; tag push + `go install` verification completed, #638 closed 2026-05-30.

#### `d5-release-verification`
- state: shipped
- depends_on: [`go-import-path-sweep`, `collector-tagging`]
- issues: #639 (closed)
- notes: ADR-0023 D5 one-time verification completed 2026-05-30 — `go get @latest` resolved, collector `go install` built, README hello-world compiled. Results recorded in #639.

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

### Activated 2026-05-29 — wave-1 items (all shipped)

#### `production-key-guard` (#476)
- state: shipped
- depends_on: []
- issues: #476 (closed)
- prs: #671 (merged)
- notes: `GeneratingKeyProvider` with production guard across all three SDKs. ADR-0018/ADR-0019 §S2.

#### `ts-hpke-hand-roll` (#473)
- state: shipped
- depends_on: []
- issues: #473 (closed)
- prs: #673 (merged)
- notes: `@hpke/core` replaced with hand-rolled HPKE from `node:crypto`. RFC 9180 §7.1.3 DeriveKeyPair gotcha documented; existing test vectors pinned. TS SDK only.

#### `sequential-emit-under-parallel` (#488)
- state: shipped
- depends_on: []
- issues: #488 (closed)
- prs: #670 (merged)
- artifacts: `ReceiptChain` for serialised receipt construction across all three SDKs.

#### `env-marker-secondary-host` (#462)
- state: shipped
- depends_on: []
- issues: #462 (closed)
- prs: #674 (merged)
- notes: env-var-driven secondary host detection in mcp-proxy.

#### `editor-integration-guides` (#495)
- state: shipped
- depends_on: []
- issues: #495 (closed)
- prs: #669 (merged)
- notes: CLI reference restructured for daemon separation (ADR-0010); MCP proxy editor integration guides for Cursor, Windsurf, VS Code Copilot, JetBrains, Cline.

#### `aivs-cg-landscape` (#622)
- state: shipped
- depends_on: []
- issues: #622 (closed)
- prs: #675 (merged)
- notes: landscape doc migrated to MDX; W3C AIVS CG entry added; review date updated.

#### `codeql-advanced-setup` (#629)
- state: shipped
- depends_on: []
- issues: #629 (closed)
- prs: #672 (merged)
- notes: CodeQL migrated to advanced setup with `paths-ignore` for docs-only PRs.

---

### Activated 2026-05-30 — wave-2 items (all shipped or closed)

#### `pkg-doc-go` (#73)
- state: shipped
- issues: #73 (closed)
- prs: #677 (merged)

#### `daemon-toml-config` (#441)
- state: shipped
- issues: #441 (closed)
- prs: #679 (merged)
- notes: daemon accepts a TOML config file; XDG-aware default path.

#### `mcp-proxy-graceful-shutdown` (#172)
- state: shipped
- issues: #172 (closed)
- prs: #690 (merged)
- notes: signal handling + graceful shutdown for mcp-proxy. Spawned #691/#692 (hardening), immediately resolved via #693/#694.

#### `mcp-proxy-world-accessible-warn` (#213)
- state: shipped
- issues: #213 (closed)
- prs: #682 (merged)
- notes: warn on world/group-accessible `~/.agent-receipts`.

#### `collector-operator-guide` (#536)
- state: shipped
- issues: #536 (closed)
- prs: #678 (merged), #681 (merged — accuracy fixes)

#### `ci-agent-receipts-guide` (#631)
- state: shipped
- issues: #631 (closed)
- prs: #680 (merged), #695 (merged — replaced with end-to-end TS walkthrough)

#### `sdk-schema-conformance-gate` (#653)
- state: shipped
- depends_on: [`ADR-0024-verification-contract`]
- issues: #653 (closed)
- prs: #696 (merged)
- notes: Gate #X — SDK output schema-conformance CI gate at release time.

#### `cross-sdk-byte-identity-gate` (#654)
- state: shipped
- depends_on: [`ADR-0024-verification-contract`]
- issues: #654 (closed)
- prs: #698 (merged)
- notes: Gate #X — cross-SDK byte-identity CI gate at release time.

#### `idempotency-key` (#480)
- state: shipped
- issues: #480 (closed 2026-05-31)
- notes: optional `idempotencyKey` field for retry deduplication; verifier surfaces duplicates as warning. All three SDKs + mcp-proxy. PR reference TBD.

#### `sql-keyword-risk-tighten` (#174)
- state: shipped
- issues: #174 (closed 2026-05-31)
- notes: word-boundary SQL pattern matching in mcp-proxy risk scorer; eliminates false positives on `update_user` style tool names. PR reference TBD.

#### `cloud-kms-signers-go` (#534 — Go module)
- state: shipped
- issues: #534 (closed 2026-05-31 — umbrella closed; TS+Py shipped in #663)
- notes: Go KMS signer adapters completed, closing the umbrella. PR reference TBD.

#### `response-hash` (#153)
- state: shipped
- issues: #153 (closed 2026-05-31)
- notes: optional `response_hash` (SHA-256, RFC 8785) in receipt outcome; hashed after redaction; verifier validates when present. PR reference TBD.

#### `mcp-proxy-db-path-fallback` (#214)
- state: closed-wontfix
- issues: #214 (closed not-planned 2026-05-31)
- notes: fail-loud on bare-filename DB path fallback. Closed as not-planned.

#### `daemon-sdk-protocol-compat-gate` (#655)
- state: shipped
- depends_on: []
- issues: #655 (closed 2026-06-03)
- prs: #705 (merged)
- notes: Gate #8 (ADR-0024) — declare daemon-protocol version ranges on SDK and daemon sides; assert intersection at release time. Needs protocol-version surface work as part of scope.

#### `sbom-deps-match-gate` (#656)
- state: shipped
- depends_on: []
- issues: #656 (closed 2026-06-01)
- prs: #699 (merged)
- notes: Gate #10 (ADR-0024) — generate per-SDK SBOM at release time; assert installed deps match declared deps; fail on unexplained eager dependencies. Supply-chain gate.

---

## Background — not in the active graph but worth noting

- **`v1-blocker` work:** #534 (AWS KMS signers) fully shipped — TS + Python via #663, Go module closed 2026-05-31. #535 (ephemeral-compute deployment guide) shipped (#660).
- **Operator tooling — SHIPPED:** #539 `agent-receipts doctor` (#661), #540 `verify-event` (#659), #552 `agent-receipts show <seq>` (#662). Outgrowth of the Max-forged-a-receipt incident.
- **Standards/positioning:** #555 (v0.3.0 blog post), #556/#557/#558 (AIVS CG contributions), #559 (draft-sharif review comment), #561 (ADR on adjacent format posture). Cadence-driven, not blocker-driven.
- **Blog campaign (Posts 3–7):** #541, #542, #543, #544 + draft PRs #442/#444 — contingent on Otto having writing time.
- **Idle PRs:** #532 (hermes-agent plugin) — open since 2026-05-22, needs a review pass or a close decision.
- **Daemon redesign:** the v2 work. Not surfaced as issues at the granularity that would let it enter this DAG; Otto's foreground design work.

---

## Next farmable (computed)

As of `2026-06-03`, **the active DAG is fully clear** — all wave-1 and wave-2 items, and all ADR-0024 verification gates (#1–#10), are shipped. `daemon-sdk-protocol-compat-gate` (#655, Gate #8) closed 2026-06-03; `sbom-deps-match-gate` (#656, Gate #10) closed 2026-06-01.

No farmable nodes remain. The next foreground work is **`daemon-v2`** — Otto's design work, not yet broken into nodes (add them here once it becomes farmable). Background items awaiting an Otto decision: PR #708 (doc-e2e CI fleet — needs repo secret + action SHA pin + permissions sign-off), idle PR #532 (hermes-agent plugin — review or close).

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
