# Agent Receipts — Roadmap

This document is the single source of truth for what's planned, what's
in-flight, and what's deferred. ADRs record decisions; this roadmap records
sequencing.

When this roadmap and an ADR disagree on sequencing, this roadmap wins
(ADRs are immutable; sequencing changes as work progresses). When they
disagree on a design decision, the ADR wins.

Each item links to a GitHub issue. Status values: `planned`, `in-progress`,
`done`, `deferred`.

---

## Milestones at a glance

| Milestone | Description | Target |
|---|---|---|
| **Post 3** | OpenClaw / Claude Code demo published to HN. Subset of v1 blockers required to avoid embarrassing failure modes in the demo. | Next |
| **v1** | Public protocol release. All known integrity gaps either fixed or explicitly documented as limitations. | After Post 3 |
| **v1.5** | Regulated-industries readiness. Items required to clear a financial services or healthcare compliance review. | After v1 |
| **v2** | Trust-model improvements beyond regulated-industries baseline. | Post-v1.5 |

---

## Regulated industries readiness (v1.5)

Items required before a bank, insurer, or healthcare provider can deploy
Agent Receipts in production. These are not optional for adoption in
regulated industries.

| Item | ADR | Issue | Status |
|---|---|---|---|
| PKCS#11 / CloudHSM `Signer` adapter | ADR-0018 | #489 | planned |
| RFC 3161 TSA timestamp anchoring (elevated from v2) | ADR-0019 § P3 | #482 | planned |
| Revocation list format and reference implementation (elevated from v2) | ADR-0019 § O1 | #483 | planned |
| `CheckpointPublisher` with object-lock reference backend (elevated from v2) | ADR-0019 § O2 | #484 | planned |
| Content-addressed payload storage (GDPR erasure) | ADR-0019 § S3 (extends) | #478 | planned |
| Standalone verifier service (separable from SDK) | new ADR needed | #490 | planned |
| Downloadable conformance test suite | ADR-0019 § S1 (extends) | #474 | planned |
| Multi-tenancy guidance — key management at scale | docs | #491 | planned |
| Regional TSA support (eIDAS, ICP-Brasil, etc.) | new ADR needed | #492 | planned |

These items have a coherent target audience (regulated-industries adopters) and
should be sequenced together rather than dripped into v2. Moving them to
v1.5 surfaces them as a deliberate milestone rather than indefinitely
deferred work.

---

## Post 3 blockers

These are the minimum subset of v1 work required before the HN-targeted
OpenClaw demo. The criterion is "would a sharp commenter immediately spot
this and undermine the protocol's credibility?"

| # | Item | ADR | Issue | Status |
|---|---|---|---|---|
| 1 | Cross-SDK canonicalisation conformance vectors | ADR-0019 § S1 | #474 | planned |
| 2 | Silent chain termination — `status` field on `agent_end` | ADR-0019 § P1 | #475 | planned |
| 3 | `GeneratingKeyProvider` unreachable in production | ADR-0019 § S2 | #476 | planned |
| 4 | Sequential receipt construction enforced under parallel tool calls | ADR-0020 | #488 | planned |

Item 4 is in this list because the OpenClaw plugin may fire concurrent tool
invocations during the demo. If concurrent emission produces a broken chain
live on HN, that is the failure mode that gets quoted in the top comment.

---

## v1 blockers (post Post 3)

Everything required for a credible public protocol release. Grouped by
workstream rather than priority — items within a workstream are ordered;
across workstreams they can be parallelised.

### Protocol semantics

| Item | ADR | Issue | Status |
|---|---|---|---|
| Explicit `sessionId` binding in verifier | ADR-0019 § P4 | #477 | planned |
| Strict `sequenceNumber` contiguity in verifier | ADR-0019 § P5 | #479 | planned |
| `idempotencyKey` field for retry deduplication | ADR-0019 § S5 | #480 | planned |

### SDK emitter layer

| Item | ADR | Issue | Status |
|---|---|---|---|
| `HttpEmitter` with sync / fire-and-forget strategies | ADR-0020 | #486 | planned |
| WAL for at-least-once delivery (long-lived + ephemeral) | ADR-0020 | #487 | planned |
| Verifier-side `incomplete_tool_roundtrip` classification | ADR-0019 § O3 → ADR-0020 | (folded into WAL issue) | planned |

### SDK payload handling

| Item | ADR | Issue | Status |
|---|---|---|---|
| Bounded `input`/`output` payload via `PayloadStrategy` | ADR-0019 § S3 | #478 | planned |

### Cross-SDK parity

| Item | ADR | Issue | Status |
|---|---|---|---|
| Python SDK `eventType` naming alignment | ADR-0019 § S1 | (folded into conformance vectors) | planned |
| `KeyProvider` / `Signer` parity across TS, Python, Go | ADR-0018 | tracked per-SDK | planned |
| `HttpEmitter` parity across TS, Python, Go | ADR-0020 | tracked per-SDK | planned |

---

## v2 — deferred

Items remaining for v2 after the regulated-industries elevation. Each has
an issue open; none are scheduled.

| Item | ADR | Issue | Status |
|---|---|---|---|
| Unauthenticated chain origin (witnessed `agent_start` or trust registry) | ADR-0019 § P2 | #481 | deferred |
| `InMemoryKeyProvider` memory safety improvements | ADR-0019 § S4 | #485 | deferred |
| Parallel sub-chains (forked chains + merge receipt) | ADR-0020 | not filed | deferred |

The following were originally targeted for v2 but elevated to v1.5
(regulated-industries readiness):

- Trusted timestamp binding (ADR-0019 § P3)
- Key revocation (ADR-0019 § O1)
- Receipt store completeness (ADR-0019 § O2)

---

## How to update this document

- A new ADR adds items here; the ADR itself only records the decision.
- An item moves between milestones (e.g. v1 → Post 3, or v1 → v2) by editing
  this file. The originating ADR is not amended.
- An item is marked `done` only when the corresponding issue is closed.
- When item numbers in ADR-0019's priority table conflict with this roadmap,
  this roadmap is authoritative.

## ADR index

| ADR | Title | Status |
|---|---|---|
| ADR-0018 | Signer abstraction and cloud-agnostic KeyProvider design | Proposed |
| ADR-0019 | Protocol integrity gaps and mitigations | Proposed |
| ADR-0020 | Emitter abstraction and remote receipt delivery | Proposed |
