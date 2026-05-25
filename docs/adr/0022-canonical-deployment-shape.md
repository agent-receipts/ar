# ADR-0022: Canonical Agent Receipts Deployment Shape (Daemon-Mediated Primary, In-Process Tutorial-Only)

## Status

Accepted

Date: 2026-05-25

## Context

The project has three documented signing modes across its SDKs and docs surfaces:

1. **In-process signing.** SDK generates the Ed25519 keypair, holds the private key in memory, signs the receipt itself. Trust boundary: the agent process. Anyone with code execution in the agent can forge receipts.
2. **Daemon-mediated signing.** SDK emits an unsigned event to a separate `agent-receipts-daemon` process over a Unix socket; the daemon holds the signing key and produces the signed receipt. Trust boundary: the daemon process, which the agent cannot reach into.
3. **Collector-mediated delivery.** SDK signs receipts in-process (or accepts pre-signed receipts) and POSTs them to a collector for storage. Trust boundary varies by deployment.

The spec opens with the position that signing keys SHOULD live outside the trust boundary of the audited component (§7.2 of v0.4.0: "the signing key SHOULD reside in a process separate from the agent, proxy, and SDK being audited"). The audit-integrity guarantee the project markets depends on this property. In-process signing satisfies "the receipt is signed" but does not satisfy "the receipt is signed by something the audited component cannot impersonate."

Despite this, the README-leading quick-start path on most SDK surfaces has historically been in-process signing, because it has no external dependencies and the simplest first-run experience. The Python README pre-PR #593 led with in-process. The site Quick Start (per SITE-P3, still unfixed) still teaches in-process signing as the recommended path, contradicting the homepage which describes in-process as the insecure posture.

This ADR records which mode is canonical and how the non-canonical modes are positioned across documentation surfaces.

## Decision

### D1. Daemon-mediated signing is the canonical Agent Receipts deployment shape

For any documented quick-start, example, integration guide, or production-oriented surface, the canonical path is daemon-mediated signing: the SDK emits events over a Unix socket (or platform-equivalent IPC) to the `agent-receipts-daemon`, which holds the Ed25519 signing key and produces signed receipts. The trust-boundary separation between the audited component and the signing process is the property that makes Agent Receipts evidence rather than self-reported claims.

Every README, every Quick Start page, every integration example, every blog post code snippet drives against the daemon by default. The first runnable code the reader sees is the daemon path.

### D2. In-process signing is tutorial and testing only

In-process signing remains a supported mode of the SDKs. It is documented as a learning aid and as a testing convenience — not as a production-suitable path.

Every documentation surface that shows the in-process pattern MUST include an explicit note, immediately adjacent to the code, that reads (or substantively equivalent):

> **Not for production.** This pattern keeps the signing key inside the agent process. Anyone with code execution in the agent can forge receipts. For real deployments, use the daemon-mediated path documented at [link].

The note is non-negotiable. Surfaces that omit it are out of compliance with this ADR.

### D3. Collector-mediated delivery is an enterprise / multi-host deployment, not the canonical first-run

Collector delivery (`HttpEmitter` → `agent-receipts-collector`) is documented as an enterprise-grade or multi-host deployment shape, not as the first-run path. It assumes a deployed collector and is appropriate where the agent host and the receipt-storage host are different. It is not the canonical path a new user encounters.

The collector itself does not weaken the trust model when used correctly (the collector typically receives already-signed receipts), but it adds operational complexity that obscures the daemon trust boundary the project's value proposition rests on. First-run docs do not lead with it.

### D4. Doc-level enforcement only; no runtime enforcement in this ADR

This ADR does not introduce runtime warnings, environment-variable gates, or other mechanical enforcement of the in-process-is-tutorial-only position. The position is documented; enforcement is by review and reader-expectation, not by code.

Adding a startup warning when in-process signing is used outside a tutorial context (e.g. without `AGENTRECEIPTS_TUTORIAL_MODE=1` or equivalent) is a possible follow-up, deferred to a separate issue. Reason for the deferral: it is not yet clear whether the runtime annoyance is proportionate to the misuse risk at the project's current adoption stage. Revisitable when the first real-world misuse is observed.

## Out of scope for this ADR

- Specific Quick Start rewrites. The Quick Start work is tracked in Closure 1 (#598) and follow-up issues; this ADR is the principle the rewrites apply.
- Per-SDK README updates. Same — Closure 1 implementation issues handle this.
- Runtime warning / tutorial-mode env var. Explicitly deferred per D4.
- Documentation of the collector deployment path itself. Independent work; this ADR only positions it relative to the daemon path.

## Consequences

- The site Quick Start gets rewritten to drive against the daemon (closes SITE-P3).
- Every SDK README that still leads with in-process signing gets reordered to lead with daemon-mediated.
- In-process examples that remain in the docs (as tutorial / testing material) carry the "Not for production" note.
- The homepage stops contradicting the Quick Start: both now describe the daemon path as canonical.
- Persona A (hands-on engineer) following the documented happy path lands on the deployment shape the project actually recommends, instead of the one it elsewhere describes as insecure.
- The collector-as-first-run pattern (which the Go SDK historically used in some examples) gets repositioned as enterprise.

## Implementation issues spawned by this ADR

Filed as separate issues, blocked on the PR that merges this ADR. Each is labeled `adr-followup`.

- Rewrite site Quick Start (`getting-started/quick-start.mdx`) to drive against the daemon, with TypeScript / Python / Go sections matching the corrected READMEs. (#616)
- Audit all README and site `.mdx` surfaces for in-process signing snippets without the "Not for production" note; add the note where missing. (#617)
- Reposition the Go SDK README's collector-leading examples to lead with the daemon path; collector example moves to an "Enterprise / multi-host" section. (#618)

---

*Closes #614 when merged.*
