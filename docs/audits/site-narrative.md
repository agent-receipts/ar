# Site Narrative Audit

**Ground truth:** `/home/user/ar/docs/positioning/pitch.md`
**Tone reference:** `/home/user/ar/site/src/content/docs/ecosystem/index.mdx`
**Audit date:** 2026-04-30
**Scope:** All pages under `/home/user/ar/site/src/content/docs/`

---

## `/home/user/ar/site/src/content/docs/index.mdx` — Introduction

**Status: drift**

- **Hero one-liner absent.** The page has no H1 matching pitch.md's locked hero: "An audit trail your agent can't tamper with". The page dives straight into a "Start with a real agent workflow" call-to-action. The canonical hero block (H1 + subhead) from pitch.md is nowhere on the site's primary landing page.

- **Value prop audience mismatch.** pitch.md names the primary audience as "platform and security teams approving agentic deployments." The introduction is written for a developer installing a tool ("If you want to try Agent Receipts in minutes, start with the MCP Proxy"). The security-team framing is absent from the first page visitors land on.

- **Daemon-isolated keys differentiator absent.** pitch.md's top differentiator is "The signing keys and receipt store live in a separate OS-level process with peer-credential attestation. A compromised agent cannot forge or suppress its own receipts." This claim — the structural reason Agent Receipts is meaningful under threat — does not appear anywhere on this page.

- **"No widely adopted open standard" claim contradicts pitch.md.** The page states (line 112–114): "there is no widely adopted open standard for recording what an agent did, why it did it, whether it succeeded, and whether it can be undone." pitch.md explicitly says Agent Receipts is NOT a competing standard: "Receipts use the same Ed25519 and SHA-256 primitives the rest of the space converged on, wrapped in the W3C Verifiable Credentials envelope. We are reusing standards, not authoring a new one." The framing of an absent standard invites the reader to interpret Agent Receipts as filling a standards gap, which is precisely the "authoring a new standard" framing pitch.md prohibits.

- **Policy enforcement claim.** The intro page bullet (line 14): "Risk scoring and policy enforcement without modifying the client or server." pitch.md is explicit: "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls." Describing the product as providing "policy enforcement" at first contact directly contradicts this.

- **Puffery in diagram caption.** (line 108): "Every step is cryptographically bound. Breaking any link is detectable." This is a reasonable technical statement and not puffery per se, but the diagram caption on line 107 — "Human authorizes → Agent acts → Receipt signed → Chain linked → Independently verifiable" — implicitly suggests human-in-the-loop authorization is built into the protocol, which it is not; the authorization step exists as a receipt field, not an enforced gate.

---

## `/home/user/ar/site/src/content/docs/getting-started/quick-start.mdx` — Quick Start

**Status: aligned**

- No narrative claims, pure procedural content. Code examples show signing keys held locally (no daemon-split pattern, but appropriate for an SDK quick-start). No enforcement or blocking language.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/overview.mdx` — MCP Proxy Overview

**Status: drift**

- **"Policy enforcement" in the description frontmatter.** The page's `description` field (line 3): "Transparent audit proxy for MCP servers with receipt signing, policy enforcement, and risk scoring." pitch.md prohibits positioning Agent Receipts as a policy engine. Describing it as providing "policy enforcement" in the meta description and page header positions the product as an enforcement tool, not an audit sink.

- **"Policy enforcement" repeated in the features list.** (line 22): "**Policy enforcement** -- YAML rules engine with four actions: pass, flag, pause (approval required), and block." The word "block" in the same bullet confirms the proxy can reject calls, meaning the mcp-proxy does perform enforcement. However, pitch.md states "Audit, not enforcement. A passive sink that records what happened." The mcp-proxy is not consistent with the "passive sink" framing — it actively blocks and pauses. This is the sharpest contradiction between product reality and positioning.

  *Note:* This may represent a genuine product-positioning tension rather than a copy error: the mcp-proxy has enforcement capabilities that pitch.md says Agent Receipts does not have. The audit flags the copy; resolving the tension requires a positioning decision.

- **"Approval workflows" as a feature.** (line 23): "**Approval workflows** -- HTTP endpoints for async approval of paused operations." Approval workflows are a form of enforcement gate (they block the call pending human decision). This reinforces the enforcement framing that pitch.md explicitly rejects.

- **Daemon-isolated keys differentiator absent.** The overview does not mention that signing keys live outside the agent process. The "why this is different" angle from pitch.md — compromised agent cannot forge receipts — is not mentioned.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/installation.mdx` — MCP Proxy Installation

**Status: aligned**

- Procedural content only. No narrative claims. No enforcement or blocking language beyond clarifying the approval workflow is opt-in.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/configuration.mdx` — MCP Proxy Configuration

**Status: drift**

- **"Block" action described without "audit-not-enforcement" context.** The actions table (lines 66–70) defines `block` as "Reject immediately with error." This is accurate product documentation, but given the pitch.md claim "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls," the presence of a `block` action with no caveat is a narrative contradiction. No qualifying language acknowledges that blocking is an opt-in layer that can be removed, not the core purpose.

- Minor: no other narrative claims. Rest of page is pure reference.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/approval-ui.mdx` — Approval Server

**Status: drift**

- **Approval server framing extends enforcement narrative.** The entire page describes a human-in-the-loop system for blocking or allowing tool calls. The page title "Approval Server" and the description "HTTP endpoints that gate paused tool calls" positions the product as an enforcement gate. pitch.md says: "Pairs with any firewall, proxy, or policy engine without overlapping their scope." Having a native approval gate built into the product overlaps with enforcement scope. No caveat on this page acknowledges the positioning or points to complementary firewall tooling.

- The page is accurate as product documentation but the tone reads as a feature showcase ("enable human-in-the-loop approvals") rather than a neutral reference.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/claude-code.mdx` — Claude Code Integration

**Status: aligned**

- The approval workflow note is clearly labeled opt-in. No overclaiming. Procedural page.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/claude-desktop.mdx` — Claude Desktop Integration

**Status: aligned**

- Procedural. Approval workflow opt-in noted. No narrative overclaiming.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/codex.mdx` — Codex Integration

**Status: aligned**

- Procedural. Approval workflow opt-in noted. No narrative overclaiming.

---

## `/home/user/ar/site/src/content/docs/mcp-proxy/remote-servers.mdx` — Remote MCP Servers

**Status: aligned**

- Procedural. No narrative claims. Caveats about OAuth visibility are honest. No enforcement language.

---

## `/home/user/ar/site/src/content/docs/specification/overview.mdx` — Specification Overview

**Status: aligned**

- Design principles are well-aligned with pitch.md: "Built on existing standards. W3C Verifiable Credentials Data Model 2.0 for structure. Ed25519 for signing. SHA-256 for hashing. RFC 3161 for trusted timestamps. No novel cryptographic primitives." (line 18). This directly matches pitch.md's "reusing standards, not authoring a new one."
- The relationship table (lines 100–109) correctly positions W3C VCs as the envelope, not a new standard.
- Tone is neutral, reference-document.

---

## `/home/user/ar/site/src/content/docs/specification/how-it-works.mdx` — How It Works

**Status: aligned**

- Technical walkthrough. No narrative overclaiming. Standards references are accurate. Tone neutral.

---

## `/home/user/ar/site/src/content/docs/specification/agent-receipt-schema.mdx` — Agent Receipt Schema

**Status: aligned**

- Pure schema reference. No marketing language.

---

## `/home/user/ar/site/src/content/docs/specification/action-taxonomy.mdx` — Action Taxonomy

**Status: aligned**

- Pure reference table. No narrative claims.

---

## `/home/user/ar/site/src/content/docs/specification/receipt-chain-verification.mdx` — Receipt Chain Verification

**Status: aligned**

- Technical verification algorithms. No marketing language. Standards use (RFC 8785, Ed25519) consistent with pitch.md.

---

## `/home/user/ar/site/src/content/docs/specification/risk-levels.mdx` — Risk Levels

**Status: drift**

- **"Authorization gates" in use cases.** (line 33): "**Authorization gates**: Require explicit user confirmation before executing `high` or `critical` actions." Risk levels as an input to authorization gates is a use case description that implies Agent Receipts is part of an enforcement or gating mechanism. pitch.md: "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls." Risk levels for filtering and alerting are appropriate; describing them as a driver for "authorization gates" implies enforcement capability that pitch.md explicitly disclaims.

---

## `/home/user/ar/site/src/content/docs/sdk-go/overview.mdx` — Go SDK Overview

**Status: aligned**

- Feature list is purely technical. No enforcement language. No narrative overclaiming.

---

## `/home/user/ar/site/src/content/docs/sdk-go/installation.mdx` — Go SDK Installation

**Status: aligned**

- Procedural.

---

## `/home/user/ar/site/src/content/docs/sdk-go/api-reference.mdx` — Go SDK API Reference

**Status: aligned**

- Pure API reference.

---

## `/home/user/ar/site/src/content/docs/sdk-ts/overview.mdx` — TypeScript SDK Overview

**Status: aligned**

- Feature list is technical and neutral.

---

## `/home/user/ar/site/src/content/docs/sdk-ts/installation.mdx` — TypeScript SDK Installation

**Status: aligned**

- Procedural.

---

## `/home/user/ar/site/src/content/docs/sdk-ts/api-reference.mdx` — TypeScript SDK API Reference

**Status: aligned**

- Pure API reference.

---

## `/home/user/ar/site/src/content/docs/sdk-py/overview.mdx` — Python SDK Overview

**Status: aligned**

- Feature list is technical and neutral.

---

## `/home/user/ar/site/src/content/docs/sdk-py/installation.mdx` — Python SDK Installation

**Status: aligned**

- Procedural.

---

## `/home/user/ar/site/src/content/docs/sdk-py/api-reference.mdx` — Python SDK API Reference

**Status: aligned**

- Pure API reference.

---

## `/home/user/ar/site/src/content/docs/dashboard/overview.mdx` — Dashboard

**Status: aligned**

- Neutral, reference-document tone. No marketing language. Early-prototype caution is honest.

---

## `/home/user/ar/site/src/content/docs/dashboard/installation.mdx` — Dashboard Installation

**Status: aligned**

- Procedural.

---

## `/home/user/ar/site/src/content/docs/openclaw/overview.mdx` — OpenClaw Overview

**Status: aligned**

- Use cases section (lines 78–84) describes post-incident review, compliance, multi-agent trust, and cost tracking. All within the audit framing. No enforcement language. Tone is neutral. The "Compliance" use case cites "W3C Verifiable Presentations for record-keeping" — consistent with pitch.md's interoperability framing.

---

## `/home/user/ar/site/src/content/docs/openclaw/installation.mdx` — OpenClaw Installation

**Status: aligned**

- Procedural. No narrative claims.

---

## `/home/user/ar/site/src/content/docs/openclaw/agent-tools.mdx` — OpenClaw Agent Tools

**Status: aligned**

- Tool reference. No narrative overclaiming. The self-audit framing ("an agent querying its own audit trail") is consistent with the audit-not-enforcement positioning.

---

## `/home/user/ar/site/src/content/docs/openclaw/cli-reference.mdx` — OpenClaw CLI Reference

**Status: aligned**

- Pure command reference (inferred — not a distinct page found, content covered in openclaw/overview.mdx and openclaw/agent-tools.mdx).

---

## `/home/user/ar/site/src/content/docs/blog/index.mdx` — Blog Index

**Status: aligned**

- One-line description per post. No narrative claims.

---

## `/home/user/ar/site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx` — OpenClaw Plugin Deep Dive

**Status: aligned**

- Technical blog post. Tone is factual and neutral — field notes style, consistent with the ecosystem page. No puffery. The comparison table between MCP Proxy and OpenClaw Plugin (lines 14–21) is neutral and honest about tradeoffs. The "What's absent" section (lines 221–228) is particularly aligned with the audit-not-enforcement positioning.

- One minor observation, not a finding: the blog post uses the config key `parameterPreview` (lines 163–174) while the installation page (openclaw/installation.mdx) names the key `parameterDisclosure` and notes `parameterPreview` was renamed in 0.6.0. The blog post has not been updated to reflect the rename. This is a documentation staleness issue rather than a narrative inconsistency.

---

## `/home/user/ar/site/src/content/docs/reference/configuration.mdx` — Reference: Configuration

**Status: aligned**

- Redirect/overview page. No narrative claims.

---

## `/home/user/ar/site/src/content/docs/reference/cli-commands.mdx` — Reference: CLI Commands

**Status: aligned**

- Pure command reference. No narrative claims.

---

## `/home/user/ar/site/src/content/docs/ecosystem/index.mdx` — Ecosystem (tone reference)

**Status: aligned** *(reference page — evaluated for tone only)*

- Neutral, reference-document tone. No puffery. Describes Agent Receipts accurately in context without overclaiming. Used as the tone model for this audit.

---

## Cross-cutting issues

### 1. Enforcement vs. audit-only — the central contradiction

pitch.md states: "**Audit, not enforcement.** A passive sink that records what happened. Pairs with any firewall, proxy, or policy engine without overlapping their scope." It also states: "Not a policy engine. Agent Receipts does not block, allow, rewrite, or rate-limit tool calls."

The mcp-proxy, however, ships with:
- A `block` policy action (`mcp-proxy/overview.mdx` line 22, `mcp-proxy/configuration.mdx` lines 66–70)
- A `pause` action that holds calls pending human approval (`mcp-proxy/overview.mdx` line 23)
- An "Approval Server" HTTP endpoint that gates tool calls (`mcp-proxy/approval-ui.mdx`)
- "policy enforcement" in the page description of the MCP Proxy overview

This gap between pitch.md's "passive sink" framing and the mcp-proxy's actual capabilities surfaces on multiple pages. The copy on these pages uses "policy enforcement" and "block" without any qualifying language that reframes these as supplemental, opt-in capabilities distinct from the core audit function.

Affected files:
- `site/src/content/docs/index.mdx` line 14 — "policy enforcement" in bullet
- `site/src/content/docs/mcp-proxy/overview.mdx` line 3 (frontmatter description) — "policy enforcement"
- `site/src/content/docs/mcp-proxy/overview.mdx` line 22 — "**Policy enforcement**" feature bullet
- `site/src/content/docs/mcp-proxy/overview.mdx` line 23 — "**Approval workflows**" feature bullet
- `site/src/content/docs/mcp-proxy/configuration.mdx` lines 66–70 — `block` action with no caveat
- `site/src/content/docs/specification/risk-levels.mdx` line 33 — "Authorization gates"

### 2. Daemon-isolated keys — pitch.md's top differentiator is absent from narrative pages

pitch.md's first and most important differentiator is the daemon-process key isolation: "The signing keys and receipt store live in a separate OS-level process with peer-credential attestation. A compromised agent cannot forge or suppress its own receipts." The hero block subhead reinforces this: "A separate daemon signs and stores a tamper-evident receipt for every tool call your agent makes. The signing keys and the receipt store live outside the agent process, so the audit trail holds up even if the agent is compromised."

This claim — the reason Agent Receipts is meaningful under adversarial conditions — does not appear on:
- `site/src/content/docs/index.mdx` (no mention)
- `site/src/content/docs/mcp-proxy/overview.mdx` (no mention)
- Any SDK overview page

The specification and how-it-works pages correctly describe the cryptographic mechanics but do not use the "keys outside the agent process" framing that is the product's core security claim.

### 3. "No widely adopted open standard" framing — residual "competing standard" language

`site/src/content/docs/index.mdx` lines 112–114: "there is no widely adopted open standard for recording what an agent did, why it did it, whether it succeeded, and whether it can be undone."

pitch.md: "Not a competing standard. Receipts use the same Ed25519 and SHA-256 primitives the rest of the space converged on, wrapped in the W3C Verifiable Credentials envelope. We are reusing standards, not authoring a new one."

The introduction frames Agent Receipts as filling a standards gap. That framing positions the project as the author of a new standard — the "competing standard" framing pitch.md explicitly prohibits. The ecosystem page does not repeat this framing; it is isolated to the introduction.

### 4. Hero block absent from the site

pitch.md defines a specific hero block:
- H1: "An audit trail your agent can't tamper with"
- Subhead: "A separate daemon signs and stores a tamper-evident receipt for every tool call your agent makes. The signing keys and the receipt store live outside the agent process, so the audit trail holds up even if the agent is compromised."

Neither the H1 nor the subhead appears anywhere on the site. The introduction page (`index.mdx`) does not use this language. The pitch.md hero is the primary vehicle for the daemon-isolation differentiator and the security-team audience frame — its absence means the site's primary entry point never delivers the canonical positioning.

### 5. Primary audience (security teams) absent from all narrative pages

pitch.md: "Built for platform and security teams approving agentic deployments."

No site page explicitly names security teams or platform teams as the target audience. The introduction, MCP proxy overview, and SDK overviews are all written for developers installing tooling. The security-team frame — the "why does this matter" angle of "your security team will block agentic features unless they can see what the agent is doing" — does not appear.

### 6. Tone: mcp-proxy pages are more promotional than reference-document standard

The ecosystem page (tone reference) is a pure landscape document: tables, factual descriptions, no calls to action. The mcp-proxy overview opens with a feature bullet list using bold feature names and promotional framing ("**Cryptographic receipts** -- Ed25519-signed W3C Verifiable Credentials"). The approval-ui page reads as a feature showcase. These pages are not egregiously promotional, but they are more marketing-forward than the ecosystem page's neutral register. The SDK overviews and specification pages are better aligned with the reference-document tone.

### 7. Blog post uses deprecated config key

`site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx` lines 163–174 uses `parameterPreview` (old key) and `parameters_preview` (old receipt field). `site/src/content/docs/openclaw/installation.mdx` lines 122–127 notes the 0.6.0 rename to `parameterDisclosure` / `parameters_disclosure`. The blog post has not been updated. This is a documentation accuracy issue that may confuse readers following the deep dive before reading the installation page.
