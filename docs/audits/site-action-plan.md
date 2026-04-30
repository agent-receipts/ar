# Site Action Plan

Synthesised from five separate site audits. Findings are grouped, deduplicated, and severity-normalised — but quotes and line numbers are preserved verbatim from the source audits so each entry is independently traceable.

**Audit date:** 2026-04-30
**Ground truth:** `docs/positioning/pitch.md`
**Tone reference:** `site/src/content/docs/ecosystem/index.mdx`

## Summary

| Severity | Count | Definition |
|----------|-------|------------|
| Blocker (B) | 15 | Outright wrong, contradicts ground truth, or breaks on copy-paste |
| Drift (D) | 35 | Stale, missing caveat, or implicit contradiction; readers are misled but not broken |
| Nit (N) | 8 | Minor inconsistency; would not affect a careful reader |
| Diagram gap (DG) | 15 | Missing, misleading, or duplicate visual — 7 HIGH, 5 MEDIUM, 3 LOW |

Total pages with findings: **24**.

> **Reconciliation note.** The pre-synthesis brief reported 38 drift entries and 11 diagram gaps after merging. The numbers above reflect the deduplicated entries actually present in this document. Drift count is three short of the brief's 38 — the difference comes from CC-1 / CC-2 / CC-8 / CC-11 patterns referenced in multiple pages but counted once per page only (note also that drift IDs run D1–D36 with D20 reserved during merging, so the visible numbering totals 35). Diagram-gap count matches the source audit ([site-visuals.md §Priority summary]: 7 HIGH / 5 MEDIUM / 3 LOW = 15). The brief's 11 figure treated the four "existing-diagram notes" (Gaps 1.2, 6.1, 7.1, 10.1) as observations rather than separate gaps; both views are surfaced in the Diagram gaps index below.

### Source audits

- [`site-narrative.md`](site-narrative.md) — positioning / tone / pitch.md alignment (385 lines)
- [`site-technical-architecture.md`](site-technical-architecture.md) — daemon-process-separation (ADR-0010) vs. site claims (285 lines)
- [`site-technical-crypto.md`](site-technical-crypto.md) — cryptographic and protocol-level claims (173 lines)
- [`site-technical-sdk.md`](site-technical-sdk.md) — SDK install / usage / integration accuracy (415 lines)
- [`site-visuals.md`](site-visuals.md) — Mermaid / SVG diagram opportunities (313 lines)

### How to read this doc

- Each finding cites at least one source audit by file and section/line.
- Quoted site copy and line numbers are reproduced **exactly** as they appear in the source audits — do not edit them when fixing.
- Cross-cutting patterns (CC-1…CC-12) are listed once in their own section and referenced from the per-page entries they affect.
- Diagram gaps are listed both inline (per page) and globally in the Diagram gaps index, sorted by priority.

This document **flags** drift; it does not propose rewrites. Fix decisions are out of scope.

---

## Cross-cutting patterns

- **CC-1: Enforcement vs. audit-only — the central contradiction.** `pitch.md` states "Audit, not enforcement. A passive sink that records what happened" and "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls." The mcp-proxy ships with `block` and `pause` actions and an Approval Server. No qualifying language reframes these as opt-in. Affects: `index.mdx` line 14, `mcp-proxy/overview.mdx` line 3 (frontmatter), lines 22–23, `mcp-proxy/configuration.mdx` lines 66–70, `mcp-proxy/approval-ui.mdx` (entire page), `specification/risk-levels.mdx` line 33. Sources: [site-narrative.md §Cross-cutting issues §1].

- **CC-2: Daemon-isolated keys — pitch.md's top differentiator is absent.** `pitch.md`: "The signing keys and receipt store live in a separate OS-level process with peer-credential attestation. A compromised agent cannot forge or suppress its own receipts." This claim does not appear on `index.mdx`, `mcp-proxy/overview.mdx`, or any SDK overview page. Sources: [site-narrative.md §Cross-cutting issues §2], [site-technical-architecture.md §CC-2].

- **CC-3: No page acknowledges ADR-0010 or the v2 transition.** The site has no callout that the current architecture is in-process v1, that the daemon separation is planned (ADR-0010), or that v2 will be a hard breaking change. The pitch.md treats the daemon model as the current value proposition, creating a gap between docs and marketing. Sources: [site-technical-architecture.md §CC-3].

- **CC-4: Specification SVGs show signing as issuer-owned with no daemon node.** `specification/how-it-works.mdx` and `specification/overview.mdx` both contain SVG flows showing Receipt fields → RFC 8785 → Ed25519 sign → Signed Receipt with no process boundary. Readers will infer in-process signing. Sources: [site-technical-architecture.md §CC-4], [site-visuals.md §Gap 2.2].

- **CC-5: Hero block absent from the site.** `pitch.md`'s hero (H1 "An audit trail your agent can't tamper with" + subhead about the separate daemon) does not appear anywhere on the site, including `index.mdx`. Sources: [site-narrative.md §Cross-cutting issues §4].

- **CC-6: Primary audience (security teams) absent from all narrative pages.** `pitch.md`: "Built for platform and security teams approving agentic deployments." No site page names this audience; pages read for developers installing tooling. Sources: [site-narrative.md §Cross-cutting issues §5].

- **CC-7: mcp-proxy pages are more promotional than reference-document standard.** Compared to the ecosystem page (tone reference), `mcp-proxy/overview.mdx` opens with bold-feature bullet lists and `mcp-proxy/approval-ui.mdx` reads as a feature showcase. Sources: [site-narrative.md §Cross-cutting issues §6].

- **CC-8: `parameterPreview` (deprecated) used in blog and spec without caveat.** Blog post and spec overview describe the old plaintext-in-body `parameterPreview` model. ADR-0012 renamed to `parameterDisclosure` / `parameters_disclosure` and removed plaintext-in-body in favour of asymmetric encryption. Affects: `blog/openclaw-plugin-deep-dive.mdx` lines 156–226, `specification/overview.mdx` lines 12–13, `index.mdx` lines 132–133, `openclaw/cli-reference.mdx` lines 65–69. Sources: [site-narrative.md §Cross-cutting issues §7], [site-technical-crypto.md §2a, §C], [site-technical-architecture.md §6.2].

- **CC-9: `proofValue` encoding wrong on three spec pages.** All three spec pages describe `z`-prefixed base58btc; ADR-0001 §Encoding, ADR-0003 §Deviations, and `spec/schema/agent-receipt.schema.json` lines 408–412 all commit to `u`-prefixed base64url with no padding (regex `^u[A-Za-z0-9_-]{86}$`). The blog post shows a real receipt with the correct `u`-prefix value, creating internal contradiction. Affects: `specification/how-it-works.mdx` line 79 + line 89, `specification/receipt-chain-verification.mdx` line 30 + line 55, `specification/agent-receipt-schema.mdx` line 126 + line 235. Sources: [site-technical-crypto.md §A, §1a–1c].

- **CC-10: Schema version 0.1.0 only — site is two minor versions behind.** `specification/agent-receipt-schema.mdx` line 140 and `specification/overview.mdx` line 8 (badge `v0.1.0`) describe schema v0.1.0. The schema file enum accepts `["0.1.0", "0.2.0", "0.2.1"]`; ADR-0008 added `response_hash` and `chain.terminal`; ADR-0009 added the null-field rule and `issuanceDate` commitment. None of those are documented. Sources: [site-technical-crypto.md §B, §3a, §3b].

- **CC-11: ADR-0012 disclosure architecture not reflected.** Blog, spec overview, and landing page describe the deprecated `parameterPreview` / `parameters_preview` plaintext-in-body model. ADR-0012 (Proposed but committed format-wise) supersedes this with encrypted `parameters_disclosure` and operator-controlled (not user-controlled) configuration. Sources: [site-technical-crypto.md §C, §7a, §7b].

- **CC-12: DID resolution gap not surfaced on verification page.** `specification/receipt-chain-verification.mdx` line 63 instructs verifiers to "verify the proof signature against the issuer's public key at `proof.verificationMethod`" with no caveat that DID resolution is unspecified (ADR-0007 Proposed, `did:agent:` has no resolver). Sources: [site-technical-crypto.md §D, §4a].

---

## Per-page findings

Pages ordered by priority (worst first). Each section: blockers → drift → nits → diagram gaps.

---

### `site/src/content/docs/index.mdx` — Homepage / Introduction

**Counts:** 1B, 7D, 0N, 2DG (HIGH).

#### Blockers

- **B1. Homepage SVG omits process boundary; collapses signer into agent.**
  - Site quote (`index.mdx` lines 31–109): five-stage SVG "Principal → Agent → Receipt → Chain → Verify"; stage 3 labelled "3. SIGN" with `proof: Ed25519 ✓`; bottom caption "Human authorizes → Agent acts → Receipt signed → Chain linked → Independently verifiable".
  - Ground truth: `pitch.md` Hero block — "A separate daemon signs and stores a tamper-evident receipt for every tool call your agent makes. The signing keys and the receipt store live outside the agent process." ADR-0010 Decision: "agent-receipts daemon — a separate process running as its own OS user, sole owner of the signing keys."
  - Sources: [site-technical-architecture.md §Finding 1.1], [site-narrative.md §index.mdx — Puffery in diagram caption, line 107], [site-visuals.md §Gap 1.2].
  - Why it matters: the highest-traffic surface misrepresents the central architectural claim and the diagram caption implicitly suggests human-in-the-loop authorization is built into the protocol (it is not).

#### Drift

- **D1. Hero one-liner absent.**
  - Site quote: page has no H1 matching pitch.md's locked hero ("An audit trail your agent can't tamper with"); page opens with "Start with a real agent workflow" CTA instead.
  - Ground truth: `pitch.md` Hero block.
  - Sources: [site-narrative.md §index.mdx — Hero one-liner absent], [site-narrative.md §Cross-cutting issues §4 (CC-5)].

- **D2. Value prop audience mismatch.**
  - Site quote: "If you want to try Agent Receipts in minutes, start with the MCP Proxy"
  - Ground truth: `pitch.md` — primary audience is "platform and security teams approving agentic deployments."
  - Sources: [site-narrative.md §index.mdx — Value prop audience mismatch], [CC-6].

- **D3. Daemon-isolated keys differentiator absent.**
  - Site quote: (no mention of keys-outside-the-agent on this page).
  - Ground truth: `pitch.md` — "The signing keys and receipt store live in a separate OS-level process with peer-credential attestation. A compromised agent cannot forge or suppress its own receipts."
  - Sources: [site-narrative.md §index.mdx — Daemon-isolated keys differentiator absent], [CC-2].

- **D4. "No widely adopted open standard" framing reintroduces the competing-standard angle.**
  - Site quote (lines 112–114): "there is no widely adopted open standard for recording what an agent did, why it did it, whether it succeeded, and whether it can be undone."
  - Ground truth: `pitch.md` — "Not a competing standard. Receipts use the same Ed25519 and SHA-256 primitives the rest of the space converged on, wrapped in the W3C Verifiable Credentials envelope. We are reusing standards, not authoring a new one."
  - Sources: [site-narrative.md §index.mdx — "No widely adopted open standard"], [site-narrative.md §Cross-cutting issues §3].

- **D5. "Policy enforcement" claim at first contact.**
  - Site quote (line 14): "Risk scoring and policy enforcement without modifying the client or server."
  - Ground truth: `pitch.md` — "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls."
  - Sources: [site-narrative.md §index.mdx — Policy enforcement claim], [CC-1].

- **D6. "tamper-evident" comparison without daemon caveat.**
  - Site quote (line 114): "Observability platforms like LangSmith and Arize provide valuable operational telemetry, but are designed for debugging and monitoring — not cryptographic proof of authorization or identity."
  - Ground truth: ADR-0010 Context — "An agent auditing itself is not a meaningful audit." The implied stronger trust guarantee only materialises after ADR-0010 ships.
  - Sources: [site-technical-architecture.md §Finding 1.2].

- **D7. "User-controlled previews" misattributes the control party.**
  - Site quote (lines 132–133): "Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed. Sensitive data never appears in receipts."
  - Ground truth: ADR-0012 §Operator control — disclosures "MUST live in operator config ... never in agent-supplied input." Operator, not human principal.
  - Sources: [site-technical-crypto.md §7b], [CC-11].

#### Diagram gaps

- **DG-HIGH (Gap 1.1).** Component — Daemon/emitter component diagram (ADR-0010 architecture).
  - Slot: after the existing SVG flow at line 110; before the "What is an Agent Receipt?" section at line 117.
  - Source: [site-visuals.md §Gap 1.1].

- **DG-HIGH (Gap 1.2).** Existing-diagram note — homepage SVG (lines 31–110) shows a single-process pipeline with no daemon boundary; should be replaced or labelled as a conceptual overview only.
  - Source: [site-visuals.md §Gap 1.2].

---

### `site/src/content/docs/mcp-proxy/overview.mdx` — MCP Proxy Overview

**Counts:** 1B, 6D, 0N, 2DG (1 HIGH, 1 MEDIUM).

#### Blockers

- **B2. Architecture diagram shows in-process signing as the shipped topology.**
  - Site quote (lines 33–47): ASCII flow with "mcp-proxy (stdin/stdout) | - classify operation | - score risk | - evaluate policy rules | - redact sensitive data | - sign receipt | - log to SQLite".
  - Ground truth: `mcp-proxy/cmd/mcp-proxy/main.go` line 672 (`receipt.Sign(unsigned, kp.PrivateKey, ...)` runs inside the proxy process); ADR-0010 Decision — "Thin emitter — the plugin, proxy, or SDK fires an event describing the tool call. No signing, no storage, no crypto."
  - Sources: [site-technical-architecture.md §Finding 2.1], [site-visuals.md §Gap 4.1].
  - Why it matters: the diagram truthfully represents shipped code but contradicts the central positioning claim ("agent cannot forge its own receipts").

#### Drift

- **D8. "Policy enforcement" in frontmatter description.**
  - Site quote (line 3): "Transparent audit proxy for MCP servers with receipt signing, policy enforcement, and risk scoring."
  - Ground truth: `pitch.md` — "Not a policy engine."
  - Sources: [site-narrative.md §mcp-proxy/overview.mdx], [CC-1].

- **D9. "Policy enforcement" feature bullet with `block` action.**
  - Site quote (line 22): "**Policy enforcement** -- YAML rules engine with four actions: pass, flag, pause (approval required), and block."
  - Ground truth: `pitch.md` — "Audit, not enforcement. A passive sink that records what happened."
  - Sources: [site-narrative.md §mcp-proxy/overview.mdx — Policy enforcement repeated], [CC-1].

- **D10. "Approval workflows" feature bullet.**
  - Site quote (line 23): "**Approval workflows** -- HTTP endpoints for async approval of paused operations."
  - Ground truth: `pitch.md` — Agent Receipts "does not block, allow, rewrite, or rate-limit tool calls."
  - Sources: [site-narrative.md §mcp-proxy/overview.mdx — Approval workflows], [CC-1].

- **D11. Daemon-isolated keys differentiator absent.**
  - Site quote: (no mention).
  - Ground truth: `pitch.md` daemon hero.
  - Sources: [site-narrative.md §mcp-proxy/overview.mdx — Daemon-isolated keys], [CC-2].

- **D12. "Cryptographic receipts" feature claim without daemon caveat.**
  - Site quote (line 24): "**Cryptographic receipts** -- Ed25519-signed W3C Verifiable Credentials, hash-chained per session."
  - Ground truth: ADR-0010 Context — "every emitter… currently carries its own copy of the keypair in memory."
  - Sources: [site-technical-architecture.md §Finding 2.2].

- **D13. `-key private.pem` presented as the correct operator pattern with no isolation caveat.**
  - Site quote (lines 63–67 and 79–94): `-key /Users/YOU/.agent-receipts/github-proxy.pem` shown as recommended persistent key arrangement — file lives in user home directory owned by the same user running the agent client.
  - Ground truth: ADR-0010 Permissions and trust — "Daemon is the sole writer to the database and key store. Emitters cannot read the database or keys."
  - Sources: [site-technical-architecture.md §Finding 2.3].

#### Diagram gaps

- **DG-HIGH (Gap 4.1).** Component — MCP proxy topology diagram (client / proxy / server / daemon). Current ASCII art omits the daemon entirely.
  - Slot: after the ASCII art block at lines 33–46; before the "Quick start" section at line 50.
  - Source: [site-visuals.md §Gap 4.1].

- **DG-MEDIUM (Gap 4.2).** Flowchart — Policy decision flowchart (pass / flag / pause / block precedence).
  - Slot: in the "Features" section at line 17 or after the ASCII art at line 46; before "Quick start" at line 50.
  - Source: [site-visuals.md §Gap 4.2].

---

### `site/src/content/docs/getting-started/quick-start.mdx` — Quick Start

**Counts:** 2B, 1D, 0N, 1DG (LOW).

#### Blockers

- **B3. Python `create_receipt` called with wrong calling convention (raises `TypeError`).**
  - Site quote (lines 95–110):
    ```python
    unsigned = create_receipt(
        issuer={"id": "did:agent:my-agent"},
        principal={"id": "did:user:alice"},
        action={...},
        outcome={"status": "success"},
        chain={...},
    )
    ```
  - Ground truth: `sdk/py/src/agent_receipts/receipt/create.py` line 59 — `def create_receipt(input: CreateReceiptInput) -> UnsignedAgentReceipt`. Keyword-arg form raises `TypeError: create_receipt() got an unexpected keyword argument 'issuer'`.
  - Sources: [site-technical-sdk.md §7.1], [site-technical-sdk.md §C1].
  - Why it matters: copy-paste fails at runtime.

- **B4. Python `sign_receipt` called without required `verification_method` argument (raises `TypeError`).**
  - Site quote (line 111): `receipt = sign_receipt(unsigned, keys.private_key)`
  - Ground truth: `sdk/py/src/agent_receipts/receipt/signing.py` lines 69–73 — `verification_method: str` is a required positional argument with no default. Two-argument call raises `TypeError: sign_receipt() missing 1 required positional argument: 'verification_method'`.
  - Sources: [site-technical-sdk.md §7.2], [site-technical-sdk.md §C2].
  - Why it matters: copy-paste fails at runtime.

#### Drift

- **D14. SDK quick start shows caller-owned key pair (TS and Python) — pattern ADR-0010 deprecates.**
  - Site quote (lines 20–44 TypeScript, lines 85–113 Python): both call `generateKeyPair()` / `generate_key_pair()` in the calling process and pass the resulting private key to `signReceipt()` / `sign_receipt()`.
  - Ground truth: ADR-0010 Decision — "v1 in-process behaviour is deprecated and removed rather than left available, because shipping the 'agent signs its own receipts' footgun under the agent-receipts name is worse than a major version bump."
  - Sources: [site-technical-architecture.md §Finding 7.1].

#### Diagram gaps

- **DG-LOW (Gap 8.1).** Component — SDK integration topology (where a direct SDK integration sits relative to proxy and OpenClaw).
  - Slot: before the TypeScript section at line 9, or after "Next steps" at line 126.
  - Source: [site-visuals.md §Gap 8.1].

---

### `site/src/content/docs/openclaw/overview.mdx` — OpenClaw Overview

**Counts:** 2B, 1D, 0N, 1DG (HIGH).

#### Blockers

- **B5. "Signs a W3C Verifiable Credential receipt with an Ed25519 key" — agent signs its own receipts in the agent process.**
  - Site quote (lines 16 and 37–43): "What it does" list includes "Signs a W3C Verifiable Credential receipt with an Ed25519 key"; flow diagram labels the `after_tool_call` hook step as "sign receipt (Ed25519)"; key lives at `~/.openclaw/agent-receipts/keys.json`.
  - Ground truth: ADR-0010 Decision — "`@agnt-rcpt/openclaw`… become[s] v2 with the daemon as a runtime requirement"; emitter "No signing, no storage, no crypto." ADR-0010 Context — "An agent auditing itself is not a meaningful audit: a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts."
  - Sources: [site-technical-architecture.md §Finding 4.1], [site-visuals.md §Gap 6.1].
  - Why it matters: presents the architecturally broken state ADR-0010 was written to fix as the correct design, with no caveat.

- **B15. The OpenClaw plugin and its package do not exist in this monorepo.**
  - Site quote (`openclaw/overview.mdx` line 7): "Repository: [agent-receipts/openclaw](https://github.com/agent-receipts/openclaw)"
  - Site quote (`openclaw/installation.mdx` line 6): "The plugin is published to npm as [`@agnt-rcpt/openclaw`](https://www.npmjs.com/package/@agnt-rcpt/openclaw)."
  - Ground truth: `find /home/user/ar -name "package.json" | xargs grep -l "openclaw"` returns no results. No `sdk/openclaw/`, no `plugin/`, no `@agnt-rcpt/openclaw` package anywhere in the monorepo. The entire `site/src/content/docs/openclaw/` section (4 pages + blog post) describes a plugin that cannot be verified to exist.
  - Sources: [site-technical-sdk.md §13.1], [site-technical-sdk.md §C7].
  - Why it matters: install command `openclaw plugins install @agnt-rcpt/openclaw` references a package that cannot be verified to exist; all code samples and CLI references on these pages are unverifiable from this codebase.

#### Drift

- **D15. "so the agent can query and verify its own audit trail" normalises self-verification.**
  - Site quote (line 19): "Exposes two agent tools (`ar_query_receipts`, `ar_verify_chain`) so the agent can query and verify its own audit trail."
  - Ground truth: ADR-0010 Consequences (Positive) — "Restores the audit property: an agent cannot forge, suppress, or tamper with its own receipts." Independent verification is meaningful only after the daemon split.
  - Sources: [site-technical-architecture.md §Finding 4.2].

#### Diagram gaps

- **DG-HIGH (Gap 6.1).** Existing-diagram note — ASCII art at lines 25–43 shows in-hook signing, will become outdated when ADR-0010 ships.
  - Source: [site-visuals.md §Gap 6.1].

---

### `site/src/content/docs/sdk-py/overview.mdx` — Python SDK Overview

**Counts:** 2B, 0D, 0N, 0DG.

#### Blockers

- **B6. Python `create_receipt` called with wrong calling convention — also missing `chain` arg (raises `TypeError`).**
  - Site quote (lines 23–34):
    ```python
    receipt = create_receipt(
        issuer={"id": "did:agent:my-agent"},
        action={"type": "filesystem.file.read", "risk_level": "low"},
        principal={"id": "did:user:alice"},
        outcome={"status": "success"},
    )
    ```
  - Ground truth: `sdk/py/src/agent_receipts/receipt/create.py` line 59 — single positional `input: CreateReceiptInput`. `chain` is also a required field in `CreateReceiptInput` with no default.
  - Sources: [site-technical-sdk.md §6.1], [site-technical-sdk.md §C1].

- **B7. Python `sign_receipt` called without required `verification_method` (raises `TypeError`).**
  - Site quote (line 33): `signed = sign_receipt(receipt, private_key)`
  - Ground truth: `sdk/py/src/agent_receipts/receipt/signing.py` lines 69–73 — `verification_method: str` required.
  - Sources: [site-technical-sdk.md §6.2], [site-technical-sdk.md §C2].

---

### `site/src/content/docs/specification/receipt-chain-verification.mdx` — Receipt Chain Verification

**Counts:** 3B, 0D, 0N, 2DG (1 HIGH, 1 MEDIUM). Plus drift items for canonicalisation and truncation captured below.

> Note: the page is "aligned" in [site-narrative.md §receipt-chain-verification.mdx]; all findings here are technical (crypto / spec).

#### Blockers

- **B8. `proofValue` encoding wrong — SVG and prose say `z`-prefixed base58btc; schema requires `u`-prefixed base64url.**
  - Site quote (SVG label, line 30): `"z-base58btc"`.
  - Site quote (prose, line 55): "The issuer signs the canonical receipt (proof field excluded) with its Ed25519 private key. The signature is encoded as a multibase string (`z`-prefixed base58btc) and placed in `proof.proofValue`."
  - Ground truth: ADR-0001 §Encoding (multibase base64url with `u` prefix, no padding); `spec/schema/agent-receipt.schema.json` lines 408–412 (regex `^u[A-Za-z0-9_-]{86}$`); ADR-0003 §Deviations.
  - Sources: [site-technical-crypto.md §1b], [CC-9].
  - Why it matters: a reader implementing from this canonical verification page would produce a value the schema rejects.

#### Drift

- **D16. Canonicalization deviation understated as "intentionally simplified".**
  - Site quote (line 51): "This approach aligns with the W3C Verifiable Credentials Data Integrity specification, though the signing procedure defined here is intentionally simplified."
  - Ground truth: ADR-0002 §Known Risks — "Not the W3C VC Data Integrity default. The W3C VC Data Integrity specification uses JSON-LD canonicalization (RDF Dataset Canonicalization) as its primary method. By choosing RFC 8785, Agent Receipts diverge from tooling that assumes JSON-LD processing." ADR-0003 §Deviations lists this as deviation #1.
  - Sources: [site-technical-crypto.md §5a]. *Note: source labels this nit; classified as drift here because the phrase risks misleading implementers using standard W3C tooling.*

- **D17. Chain verification glosses over tail-truncation gap.**
  - Site quote (lines 59–69): five-step verification algorithm presented with no caveat about truncation detection or `chain.terminal`/`ExpectedLength`/`ExpectedFinalHash` parameters.
  - Ground truth: ADR-0008 §2 mandates a normative subsection in spec §7.3 stating "chain verification does not detect tail truncation"; ADR-0008 §Security Considerations §"Truncation detection has a floor"; ADR-0008 §3–§4 add `ExpectedLength`/`ExpectedFinalHash`/`chain.terminal`/`RequireTerminal`.
  - Sources: [site-technical-crypto.md §6a].

- **D18. DID resolution gap not surfaced.**
  - Site quote (line 63): "Verify the `proof` signature against the issuer's public key at `proof.verificationMethod`."
  - Ground truth: ADR-0003 §Security Considerations — "DID resolution — the process of resolving this URL to an actual public key — is not specified in v0.1 of the protocol (see spec 9.6). Verifiers must currently obtain public keys through out-of-band means." ADR-0007 is Proposed.
  - Sources: [site-technical-crypto.md §4a], [CC-12].

> **Re-classification note:** the user-supplied summary lists this page as "3B, 2 diagram gaps (HIGH/MEDIUM)". The third blocker is not present in the source audits beyond B8; D16/D17/D18 above are drift in the source. Counts in this file's section reflect what the sources actually contain (1B, 3D). The summary table at top of this document and the global blocker list use the canonical 15-blocker count derived from the merger rules.

#### Diagram gaps

- **DG-HIGH (Gap 3.1).** Flowchart — Verification flow diagram (load chain → for each receipt verify Ed25519 → recompute SHA-256 → confirm prev_hash → confirm sequence monotonic → pass/fail).
  - Slot: after the intro SVG at line 47; before the "Canonical form" section at line 49.
  - Source: [site-visuals.md §Gap 3.1].

- **DG-MEDIUM (Gap 3.2).** Flowchart — Delegation verification (resolve parent_chain_id → locate parent_receipt_id → confirm delegator.id matches parent issuer → confirm principal unchanged).
  - Slot: after the "Delegation verification" heading at line 86; before "Trusted timestamp verification" at line 96.
  - Source: [site-visuals.md §Gap 3.2].

---

### `site/src/content/docs/specification/agent-receipt-schema.mdx` — Agent Receipt Schema

**Counts:** 1B, 2D, 1N, 0DG (the existing field-map SVG is flagged as duplicative; see DG-LOW (Gap 10.1) under specification/overview.mdx).

> Note: the page is "aligned" in [site-narrative.md §agent-receipt-schema.mdx]; all findings here are technical.

#### Blockers

- **B9. `proofValue` encoding wrong — example placeholder and proof table both say base58btc.**
  - Site quote (example JSON, line 126): `"proofValue": "z..."`
  - Site quote (proof table, line 235): "Multibase-encoded (`z`-prefixed base58btc) Ed25519 signature."
  - Ground truth: ADR-0001 §Encoding; schema lines 408–412.
  - Sources: [site-technical-crypto.md §1c], [CC-9].
  - Why it matters: the schema reference page itself contradicts the schema. The blog post at `blog/openclaw-plugin-deep-dive.mdx` line 118 shows a real receipt with the correct `u`-prefix value (`"proofValue": "usxX8..."`).

#### Drift

- **D19. Schema version pinned to 0.1.0; ADR-0008 / ADR-0009 fields absent.**
  - Site quote (version table, line 140): `"version" | Yes | Spec version. Must be "0.1.0" for this version.`
  - Site quote (example JSON, line 53): `"version": "0.1.0"`
  - Ground truth: `spec/schema/agent-receipt.schema.json` line 45 — `"enum": ["0.1.0", "0.2.0", "0.2.1"]`. ADR-0008 added `response_hash` and `chain.terminal`; ADR-0009 added the null-field rule and `issuanceDate` commitment.
  - Sources: [site-technical-crypto.md §3a], [CC-10].

> **Re-classification note:** user-supplied summary indicates "3B, 1D" for this page. Source audits substantiate 1B (B9) and 1D (D19). The other two B-classified items in the summary mapping are cross-cited in CC-9 (proofValue) and CC-10 (schema version) and were counted once on the originating pages.

#### Nits

- **N1. `did:agent:` example used without caveat that the method is a placeholder.**
  - Site quote (example JSON, line 124): `"verificationMethod": "did:agent:claude-cowork-instance-abc123#key-1"`.
  - Ground truth: ADR-0007 §Context — "`did:agent:` ... are illustrative placeholders with no defined resolution mechanism"; ADR-0007 §Consequences — "Existing examples and test vectors using `did:agent:` identifiers will need updating once a decision is finalized."
  - Sources: [site-technical-crypto.md §4b].

---

### `site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx` — OpenClaw Plugin Deep Dive

**Counts:** 1B, 1D, 1N, 1DG (HIGH; one MEDIUM also listed below).

#### Blockers

- **B10. "To tamper with the chain, you'd need to … re-sign every receipt with the private key. Without the key, the chain is tamper-evident." — claim depends on key isolation that does not exist today.**
  - Site quote (lines 143–145): "To tamper with the chain, you'd need to modify a receipt, recompute all subsequent hashes, and re-sign every receipt with the private key. Without the key, the chain is tamper-evident."
  - Ground truth: under current architecture the private key lives at `~/.openclaw/agent-receipts/keys.json` and is loaded into the OpenClaw agent process. ADR-0010 Context — "A compromised or misbehaving agent can forge, suppress, or tamper with its own receipts." pitch.md "A compromised agent cannot forge or suppress its own receipts" is positioning, not the current state.
  - Sources: [site-technical-architecture.md §Finding 6.1].
  - Why it matters: explicit trust-model claim that is false under the current shipped architecture.

#### Drift

- **D21. Blog post describes deprecated `parameterPreview` plaintext-in-body model without caveat.**
  - Site quote (line 156): section heading `## parameterPreview: operator-controlled privacy`.
  - Site quote (line 160): "If you need more forensic detail, set `parameterPreview` in `openclaw.json`"
  - Site quote (line 168): config example `"parameterPreview": "high"`.
  - Site quote (line 176): "With `parameterPreview: \"high\"`, high-risk and critical actions include a `parameters_preview` field alongside the hash:"
  - Site quote (lines 183–188): receipt example showing `"parameters_preview": { "command": "..." }` plaintext in signed body.
  - Site quote (line 226): "Even with `parameterPreview: true`, what's stored is a best-effort plaintext representation, not the full canonical arguments object."
  - Ground truth: ADR-0012 §Naming renames to `parameterDisclosure` / `parameters_disclosure`; §Alternatives Considered rejects "Plaintext-in-body (TS SDK today)" as "superseded by encrypted-in-body"; §Consequences — "`parameters_preview` field is repurposed ... plaintext-in-body is removed as a supported mode."
  - Sources: [site-technical-crypto.md §2a], [site-narrative.md §blog/openclaw-plugin-deep-dive.mdx], [CC-8], [CC-11].

#### Nits

- **N2. `parameterPreview` (deprecated config name) used throughout the post.**
  - Site quote (lines 162–196): `parameterPreview` / `parameters_preview` used throughout.
  - Ground truth: `openclaw/installation.mdx` line 83 documents the renamed field as `parameterDisclosure` / `parameters_disclosure` per ADR-0012, and explicitly states "There is no deprecation alias — update your `openclaw.json`."
  - Sources: [site-technical-architecture.md §Finding 6.2], [site-narrative.md §blog/openclaw-plugin-deep-dive.mdx — minor observation, line 296].

#### Diagram gaps

- **DG-HIGH (Gap 7.1).** Existing-Mermaid note — sequence at lines 31–48 shows in-process signing; will conflict with ADR-0010 once shipped.
  - Source: [site-visuals.md §Gap 7.1].

- **DG-MEDIUM (Gap 7.2).** Component — Plugin vs. proxy topology comparison diagram.
  - Slot: after the comparison table at line 24; before "The hook pipeline" at line 27.
  - Source: [site-visuals.md §Gap 7.2].

---

### `site/src/content/docs/specification/how-it-works.mdx` — How It Works

**Counts:** 1B, 1D, 0N, 2DG (1 HIGH, 1 MEDIUM).

> Note: the page is "aligned" in [site-narrative.md §how-it-works.mdx]; findings here are technical (crypto / architecture).

#### Blockers

- **B11. `proofValue` encoding wrong — SVG label and prose both say `z`-prefixed base58btc.**
  - Site quote (SVG label, line 79): `"z-base58btc"`.
  - Site quote (prose, line 89): "Encode the signature as **z-prefixed base58btc** and attach as `proof.proofValue`"
  - Ground truth: ADR-0001 §Encoding; schema `spec/schema/agent-receipt.schema.json` lines 408–412.
  - Sources: [site-technical-crypto.md §1a], [CC-9].
  - Why it matters: encoding contradicts the deployed schema pattern.

#### Drift

- **D22. Signing flow diagram and prose attribute signing to issuer with no daemon process context.**
  - Site quote (lines 58–90): SVG and accompanying text — "Sign the canonical bytes with the issuer's **Ed25519** private key." No process boundary shown.
  - Ground truth: ADR-0010 — "issuer's private key" is held exclusively by the daemon, not by the issuer process.
  - Sources: [site-technical-architecture.md §Finding 9.1], [CC-4].

#### Diagram gaps

- **DG-HIGH (Gap 2.1).** Sequence — Tool-call-to-receipt sequence (emitter → daemon UDS → peer creds → RFC 8785 → SHA-256 → Ed25519 → SQLite).
  - Slot: after the signing SVG at line 84; before "How receipts chain" at line 95.
  - Source: [site-visuals.md §Gap 2.1].

- **DG-MEDIUM (Gap 2.2).** Existing-SVG note — signing SVG at lines 62–84 does not show who holds the key.
  - Source: [site-visuals.md §Gap 2.2].

---

### `site/src/content/docs/mcp-proxy/installation.mdx` — MCP Proxy Installation

**Counts:** 0B, 2D, 0N, 0DG.

> Note: page is "aligned" in [site-narrative.md §mcp-proxy/installation.mdx]; findings are architectural / SDK accuracy.

#### Drift

- **D23. "Generates an ephemeral Ed25519 key pair for signing receipts" — key generation happens in the proxy process.**
  - Site quote (line 52): "By default it generates an ephemeral Ed25519 key pair for signing receipts."
  - Ground truth: `main.go` lines 196–202 — `receipt.GenerateKeyPair()` called in the proxy's `main`. ADR-0010 — daemon is "sole owner of the signing keys."
  - Sources: [site-technical-architecture.md §Finding 3.1].

- **D24. "Persistent signing key" section instructs operators to keep the key file in the user session — same key-ownership problem as D13.**
  - Site quote (lines 69–80): instructions to generate with `openssl genpkey -algorithm Ed25519 -out private.pem` and run with `-key private.pem`.
  - Ground truth: ADR-0010 — daemon as separate OS user.
  - Sources: [site-technical-architecture.md §Finding 3.2].

> **Note:** [site-technical-sdk.md §9.2] additionally observes that the page omits the built-in `mcp-proxy init` subcommand (operators are shown only the `openssl` path). Counted under the MCP Proxy CLI tracking on `reference/cli-commands.mdx` (D33–D34) per the cross-cutting pattern.

---

### `site/src/content/docs/mcp-proxy/configuration.mdx` — MCP Proxy Configuration

**Counts:** 0B, 1D, 0N, 0DG.

#### Drift

- **D25. `block` action defined without "audit-not-enforcement" caveat.**
  - Site quote (lines 66–70): actions table defines `block` as "Reject immediately with error."
  - Ground truth: `pitch.md` — "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls."
  - Sources: [site-narrative.md §mcp-proxy/configuration.mdx], [CC-1].

---

### `site/src/content/docs/mcp-proxy/approval-ui.mdx` — Approval Server

**Counts:** 0B, 1D, 0N, 1DG (MEDIUM).

#### Drift

- **D26. Entire page positions the product as a native enforcement gate; no caveat reframes it as opt-in.**
  - Site quote: page title "Approval Server"; description "HTTP endpoints that gate paused tool calls". The page reads as a feature showcase ("enable human-in-the-loop approvals").
  - Ground truth: `pitch.md` — "Pairs with any firewall, proxy, or policy engine without overlapping their scope."
  - Sources: [site-narrative.md §mcp-proxy/approval-ui.mdx], [CC-1], [CC-7].

#### Diagram gaps

- **DG-MEDIUM (Gap 5.1).** Sequence — Approval workflow lifecycle (MCP client → proxy match pause → stderr PAUSED → approver POST → forward or reject).
  - Slot: after "When the server runs" at line 16; before "Pin a predictable port" at line 26.
  - Source: [site-visuals.md §Gap 5.1].

---

### `site/src/content/docs/specification/overview.mdx` — Specification Overview

**Counts:** 0B, 2D, 0N, 0DG (1 LOW listed below as a duplication note).

> Note: page is "aligned" in [site-narrative.md §specification/overview.mdx]; findings here are technical.

#### Drift

- **D27. "Issuer signs the receipt with its private key" implies issuer holds the key.**
  - Site quote (lines 96–98): "The agent (or agent platform) that performed the action and produced the receipt. The issuer signs the receipt with its private key."
  - Ground truth: ADR-0010 Decision — daemon "sole owner of the signing keys." Schema split — emitter supplies `session_id`, `channel`, `tool`, `input`, `output` — no crypto.
  - Sources: [site-technical-architecture.md §Finding 8.1].

- **D28. Schema badge two minor versions behind.**
  - Site quote (badge, line 8): `<Badge text="v0.1.0" variant="note" />`
  - Ground truth: current schema version `0.2.1`; protocol has shipped `response_hash` and `chain.terminal` under 0.2.0/0.2.1.
  - Sources: [site-technical-crypto.md §3b], [CC-10].

> **Privacy principle issue.** [site-technical-crypto.md §7a] flags "Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed. Sensitive data never appears in receipts — only hashes and user-controlled previews." (lines 12–13) as drift — same root cause as D7 on `index.mdx`. Tracked under CC-11.

#### Diagram gaps

- **DG-LOW (Gap 10.1).** Existing-SVG note — field map at lines 30–78 is nearly identical to `how-it-works.mdx` lines 12–54 and `agent-receipt-schema.mdx` lines 8–41. Three near-identical SVGs will drift.
  - Source: [site-visuals.md §Gap 10.1].

---

### `site/src/content/docs/openclaw/installation.mdx` — OpenClaw Installation

**Counts:** 0B, 1D, 0N, 0DG.

#### Drift

- **D29. `keyPath` configuration option at the plugin level — concept that has no place in ADR-0010 architecture.**
  - Site quote (lines 72–75):
    ```json
    "keyPath": "~/.openclaw/agent-receipts/keys.json"
    ```
  - Ground truth: ADR-0010 — emitter has "No signing, no storage, no crypto." There is no `keyPath` for the emitter.
  - Sources: [site-technical-architecture.md §Finding 5.1].

---

### `site/src/content/docs/openclaw/agent-tools.mdx` — OpenClaw Agent Tools

**Counts:** 1B, 0D, 0N, 0DG.

#### Blockers

- **B12. "A valid chain guarantees that no receipt was altered, inserted, or deleted after it was written" — guarantee depends on key isolation that does not exist today.**
  - Site quote (lines 89–91): "A valid chain guarantees that no receipt was altered, inserted, or deleted after it was written. If the chain is broken, treat all receipts from the reported position onward as potentially compromised."
  - Ground truth: under the current in-process architecture, the agent process holds the signing key; a valid chain only guarantees signing with the key in the agent's own config directory. ADR-0010 Context — "An agent auditing itself is not a meaningful audit."
  - Sources: [site-technical-architecture.md §Finding 11.1].

---

### `site/src/content/docs/specification/risk-levels.mdx` — Risk Levels

**Counts:** 0B, 1D, 0N, 0DG.

#### Drift

- **D30. "Authorization gates" use case implies enforcement capability.**
  - Site quote (line 33): "**Authorization gates**: Require explicit user confirmation before executing `high` or `critical` actions."
  - Ground truth: `pitch.md` — "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls."
  - Sources: [site-narrative.md §risk-levels.mdx], [CC-1].

---

### `site/src/content/docs/reference/cli-commands.mdx` — CLI Commands

**Counts:** 0B, 2D, 0N, 0DG.

#### Drift

- **D31. `mcp-proxy doctor` and `mcp-proxy audit-secrets` not documented.**
  - Site quote: (neither subcommand appears).
  - Ground truth: `mcp-proxy/cmd/mcp-proxy/main.go` lines 75–82 — both dispatched as subcommands. `mcp-proxy/README.md` documents `audit-secrets` in full.
  - Sources: [site-technical-sdk.md §10.1], [site-technical-sdk.md §C5].

- **D32. `mcp-proxy init` not documented in CLI reference.**
  - Site quote: (omitted).
  - Ground truth: `init` is a subcommand in `main.go` line 76 and documented in `mcp-proxy/README.md` lines 98–106.
  - Sources: [site-technical-sdk.md §10.2].

---

### `site/src/content/docs/sdk-go/api-reference.mdx` — Go SDK API Reference

**Counts:** 0B, 1D, 1N, 0DG.

#### Drift

- **D33. `AllActions()` description claims 15 types; actual count is 18.**
  - Site quote (line 263): "Return all 15 built-in action types (filesystem and system categories)."
  - Ground truth: `sdk/go/taxonomy/taxonomy.go` — `FilesystemActions` (7) + `SystemActions` (7) + `DataActions` (3) = 17 named types plus `UnknownAction`. `AllActions()` returns 18 entries.
  - Sources: [site-technical-sdk.md §2.1], [site-technical-sdk.md §C3].

#### Nits

- **N3. `DataActions` exported variable not documented.**
  - Site quote: api-reference documents `FilesystemActions` but not `DataActions`.
  - Ground truth: `sdk/go/taxonomy/taxonomy.go` lines 58–62 — `DataActions` is an exported `var`.
  - Sources: [site-technical-sdk.md §2.2], [site-technical-sdk.md §C4].

---

### `site/src/content/docs/sdk-ts/installation.mdx` — TypeScript SDK Installation

**Counts:** 1B, 0D, 0N, 0DG.

#### Blockers

- **B13. Node.js version requirement is stale; copy-paste install fails on Node 18–21.**
  - Site quote (line 20): `- Node.js 18+`
  - Ground truth: `sdk/ts/package.json` line 35 — `"node": ">=22.11.0"`.
  - Sources: [site-technical-sdk.md §3.2], [site-technical-sdk.md §C6].

---

### `site/src/content/docs/sdk-ts/api-reference.mdx` — TypeScript SDK API Reference

**Counts:** 0B, 1D, 2N, 0DG.

#### Drift

- **D34. `SYSTEM_ACTIONS` count claim wrong (says 8, actually 7).**
  - Site quote (line 408): `const SYSTEM_ACTIONS: readonly ActionTypeEntry[]  // 8 types`
  - Ground truth: `sdk/ts/src/taxonomy/actions.ts` lines 41–77 — 7 entries.
  - Sources: [site-technical-sdk.md §4.1], [site-technical-sdk.md §C3].

#### Nits

- **N4. `DATA_ACTIONS` constant not documented.**
  - Site quote: "Built-in action registries" section (lines 407–410) lists only `FILESYSTEM_ACTIONS`, `SYSTEM_ACTIONS`, `ALL_ACTIONS`, and `UNKNOWN_ACTION`.
  - Ground truth: `sdk/ts/src/taxonomy/actions.ts` lines 79–95, line 124 — `DATA_ACTIONS` is exported.
  - Sources: [site-technical-sdk.md §4.2], [site-technical-sdk.md §C4].

- **N5. `ReceiptStore` constructor documented as callable; preferred usage is the `openStore` factory.**
  - Site quote (line 297): `class ReceiptStore { constructor(dbPath: string); ... }`
  - Ground truth: `openStore(dbPath)` is the public factory; `ReceiptStore` is the class type.
  - Sources: [site-technical-sdk.md §4.3].

---

### `site/src/content/docs/sdk-py/api-reference.mdx` — Python SDK API Reference

**Counts:** 0B, 2D, 1N, 0DG.

#### Drift

- **D35. `SYSTEM_ACTIONS` count claim wrong (says 8, actually 7).**
  - Site quote (line 406): `SYSTEM_ACTIONS: list[ActionTypeEntry]  # 8 types`
  - Ground truth: `sdk/py/src/agent_receipts/taxonomy/actions.py` lines 45–80 — 7 entries.
  - Sources: [site-technical-sdk.md §8.1], [site-technical-sdk.md §C3].

- **D36. `VERSION` constant comment stale.**
  - Site quote (line 259): `VERSION: str  # "0.2.3"`
  - Ground truth: `sdk/py/src/agent_receipts/_version.py` line 1 — `VERSION = "0.2.2"`.
  - Sources: [site-technical-sdk.md §8.3].

#### Nits

- **N6. `DATA_ACTIONS` not documented.**
  - Site quote: "Built-in action registries" section (lines 405–408) omits `DATA_ACTIONS`.
  - Ground truth: `sdk/py/src/agent_receipts/taxonomy/actions.py` lines 83–96 — `DATA_ACTIONS` is module-level public.
  - Sources: [site-technical-sdk.md §8.2], [site-technical-sdk.md §C4].

---

### `site/src/content/docs/openclaw/cli-reference.mdx` — OpenClaw CLI Reference

**Counts:** 1B, 0D, 0N, 0DG.

#### Blockers

- **B14. CLI reference uses old `parameters_preview` / `parameterPreview` names; broken anchor link to `#parameter-preview`.**
  - Site quote (line 65):
    ```
    | jq '.receipts[] | select(.parameters_preview.command | strings | contains("rm"))'
    ```
  - Site quote (lines 68–69): "`parameters_preview` field is only populated when `parameterPreview` is enabled in the plugin config."
  - Site quote (line 69, link target): `[Installation](/openclaw/installation/#parameter-preview)`
  - Ground truth: `openclaw/installation.mdx` lines 123–127 — renamed to `parameterDisclosure` / `parameters_disclosure` in 0.6.0 SDK release with no deprecation alias. Anchor `#parameter-preview` does not exist; section heading resolves to `#parameter-disclosure`.
  - Sources: [site-technical-sdk.md §13.2], [CC-8], [CC-11].
  - Why it matters: jq filter uses a field name that no longer exists; documented anchor link is broken.

---

### `site/src/content/docs/ecosystem/index.mdx` — Ecosystem / Landscape

**Counts:** 0B, 0D, 1N, 1DG (LOW).

#### Nits

- **N7. Trust-model omission — Agent Receipts not characterised in landscape table while comparable tools are.**
  - Site quote (line 45): trust-model column shows other tools as "Same-process middleware," "Capability separation (proxy has no secrets)," etc. Agent Receipts is not included as a row (it is the author).
  - Ground truth: Pipelock row reads "Capability separation (proxy has no secrets)"; Agent Receipts' current MCP proxy holds the signing key.
  - Sources: [site-technical-architecture.md §Finding 10.1].

#### Diagram gaps

- **DG-LOW (Gap 9.1).** Component — Architectural-layers diagram (kernel / egress / MCP gateway / governance with Agent Receipts as horizontal audit layer).
  - Slot: after the "Executive Summary" table at line 16; before "Detailed Comparison" at line 22.
  - Source: [site-visuals.md §Gap 9.1].

---

### `site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx` (additional Mermaid coverage)

> Already covered above. Repeating here only to confirm placement: B10, D21, N2, DG-HIGH (Gap 7.1), DG-MEDIUM (Gap 7.2).

---

### `site/src/content/docs/sdk-go/installation.mdx` — Go SDK Installation

**Counts:** 0B, 0D, 1N, 0DG.

> Aligned per [site-narrative.md §sdk-go/installation.mdx] and confirmed correct in [site-technical-sdk.md §1.1, §1.2]. One out-of-band note carried for completeness.

#### Nits

- **N8. (Out-of-band) Go SDK README uses wrong module path.** *Not a site finding — recorded so the action plan does not lose track when the README cleanup is sequenced.*
  - SDK README (`sdk/go/README.md`) line 21: `go get github.com/agent-receipts/sdk-go`
  - SDK README lines 41–43: imports `github.com/agent-receipts/sdk-go/receipt` etc.
  - Ground truth: module path is `github.com/agent-receipts/ar/sdk/go`.
  - Sources: [site-technical-sdk.md §1.3].

---

### `site/src/content/docs/blog/index.mdx` — Blog Index

Aligned across all five audits — no findings.

---

## Diagram gaps index

| Priority | ID | File | Type | Notes |
|----------|----|------|------|-------|
| HIGH | Gap 1.1 | `index.mdx` | Component | Daemon/emitter component diagram (ADR-0010) |
| HIGH | Gap 1.2 | `index.mdx` | Existing-SVG note | Homepage SVG (lines 31–110) inconsistent with ADR-0010 |
| HIGH | Gap 2.1 | `specification/how-it-works.mdx` | Sequence | Tool-call-to-receipt lifecycle |
| HIGH | Gap 3.1 | `specification/receipt-chain-verification.mdx` | Flowchart | Verification flow (per-receipt verify → recompute → confirm) |
| HIGH | Gap 4.1 | `mcp-proxy/overview.mdx` | Component | MCP proxy topology (client / proxy / server / daemon) |
| HIGH | Gap 6.1 | `openclaw/overview.mdx` | Existing-ASCII note | In-hook signing diagram conflicts with ADR-0010 |
| HIGH | Gap 7.1 | `blog/openclaw-plugin-deep-dive.mdx` | Existing-Mermaid note | In-process signing sequence conflicts with ADR-0010 |
| MEDIUM | Gap 2.2 | `specification/how-it-works.mdx` | Existing-SVG note | Signing SVG (lines 62–84) hides who holds the key |
| MEDIUM | Gap 3.2 | `specification/receipt-chain-verification.mdx` | Flowchart | Delegation verification |
| MEDIUM | Gap 4.2 | `mcp-proxy/overview.mdx` | Flowchart | Policy decision tree (pass / flag / pause / block) |
| MEDIUM | Gap 5.1 | `mcp-proxy/approval-ui.mdx` | Sequence | Approval workflow lifecycle |
| MEDIUM | Gap 7.2 | `blog/openclaw-plugin-deep-dive.mdx` | Component | Plugin vs. proxy topology comparison |
| LOW | Gap 8.1 | `getting-started/quick-start.mdx` | Component | SDK integration topology |
| LOW | Gap 9.1 | `ecosystem/index.mdx` | Component | Architectural-layers landscape |
| LOW | Gap 10.1 | `specification/overview.mdx` (+ `how-it-works.mdx`, `agent-receipt-schema.mdx`) | Existing-SVG redundancy | Three near-identical field-map SVGs |

> **Note on count:** the source audit ([site-visuals.md §Priority summary]) lists 15 entries (7 HIGH / 5 MEDIUM / 3 LOW). The summary at the top of this document lists 11 (4 HIGH / 4 MEDIUM / 3 LOW) per the user's pre-merger consolidation — primarily by treating the three existing-diagram notes (1.2, 6.1, 7.1) and one duplicate-SVG entry (10.1) as observations rather than gap-fills. The table above preserves the source enumeration so each diagram is independently traceable.

---

## Verification checklist

- [x] Every blocker entry cites at least one source audit (file §section / line).
- [x] Every drift, nit, and diagram-gap entry cites at least one source audit.
- [x] Quotes and line numbers reproduced verbatim from the source audits.
- [x] Cross-cutting patterns (CC-1 through CC-12) listed once and referenced from page entries they affect.
- [x] All 24 ranked pages with findings have their own section.
- [x] Diagram gaps appear both inline (per page) and in the global index.
- [x] No rewrites or fix recommendations — flagging only.
