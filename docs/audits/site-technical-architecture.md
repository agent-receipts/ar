# Site Technical Architecture Audit

**Scope:** Daemon-process-separation story (ADR-0010) vs. site claims.
**Ground truth sources:** `docs/positioning/pitch.md` (locked positioning), `docs/adr/0010-daemon-process-separation.md` (status: Proposed — not yet shipped).
**Code spot-check:** `mcp-proxy/cmd/mcp-proxy/main.go` line 672 confirms signing currently happens in-process inside the mcp-proxy binary. `mcp-proxy/internal/audit/` contains no IPC emitter code. Current architecture is in-process signing by each integration — exactly what ADR-0010 proposes to replace.
**Date:** 2026-04-30

---

## 1. `site/src/content/docs/index.mdx` — Homepage

### Finding 1.1 — SVG flow diagram omits process boundary (blocker)

**Site claim:** `index.mdx` lines 31–109. The SVG diagram shows a five-stage flow: "Principal → Agent → Receipt → Chain → Verify". Stage 3 is labelled "3. SIGN" and shows a receipt box with `proof: Ed25519 ✓`. The bottom caption reads "Human authorizes → Agent acts → Receipt signed → Chain linked → Independently verifiable".

**Problem:** The diagram shows no daemon, no process boundary, and no separation between the "Agent" node (stage 2) and the "Receipt signed" node (stage 3). A reader will reasonably interpret the diagram as: the agent signs its own receipt. The pitch.md hero block states "A separate daemon signs and stores a tamper-evident receipt for every tool call your agent makes. The signing keys and the receipt store live outside the agent process." The diagram contradicts this directly — it collapses the agent and the signer into the same flow lane.

**Ground truth:** `pitch.md` (Hero block): "A separate daemon signs and stores…". ADR-0010 Decision section: "agent-receipts daemon — a separate process running as its own OS user, sole owner of the signing keys." The daemon is not yet shipped (ADR status: Proposed), but the positioning is locked.

**Severity: blocker.** The homepage diagram is the highest-traffic surface and it misrepresents the central architectural claim.

---

### Finding 1.2 — "tamper-evident" without daemon caveat (drift)

**Site claim:** `index.mdx` line 114: "Observability platforms like LangSmith and Arize provide valuable operational telemetry, but are designed for debugging and monitoring — not cryptographic proof of authorization or identity." Implicit in the surrounding copy is that Agent Receipts provides stronger guarantees.

**Problem:** The page implies Agent Receipts currently delivers a stronger trust guarantee than in-process logging tools. Per pitch.md, the key differentiator is "Daemon-isolated keys. A compromised agent cannot forge or suppress its own receipts." Under the current shipped architecture (in-process signing), this claim does not hold. The stronger guarantee only materialises after ADR-0010 is implemented.

**Ground truth:** ADR-0010 Context: "An agent auditing itself is not a meaningful audit: a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts." This is the current state of the shipped code.

**Severity: drift.** Not an outright false statement, but the page sets up a trust contrast that is not yet structurally realised.

---

## 2. `site/src/content/docs/mcp-proxy/overview.mdx` — MCP Proxy Overview

### Finding 2.1 — Architecture diagram shows in-process signing as current shipped topology (blocker)

**Site claim:** `mcp-proxy/overview.mdx` lines 33–47:

```
MCP Client (Claude Desktop / Claude Code)
    |
    v
 mcp-proxy (stdin/stdout)
    |  - classify operation
    |  - score risk
    |  - evaluate policy rules
    |  - redact sensitive data
    |  - sign receipt
    |  - log to SQLite
    v
 MCP Server (any)
```

**Problem:** This diagram accurately describes the current shipped code (`main.go` line 672: `receipt.Sign(unsigned, kp.PrivateKey, ...)` runs inside the proxy process). However, it shows the proxy as owning the private key and signing receipts in-process — the architecture ADR-0010 calls out as the broken state: "A compromised or misbehaving agent can forge, suppress, or tamper with its own receipts." The proxy is in the same trust boundary as the agent (it is the MCP transport layer for the agent). Positioning pitch is "agent cannot forge its own receipts" — that claim is not true today for the MCP proxy path.

**Ground truth:** `mcp-proxy/cmd/mcp-proxy/main.go` lines 190–202 (key loaded or generated in-process); line 672 (signing in-process). ADR-0010 Decision: "Thin emitter — the plugin, proxy, or SDK fires an event describing the tool call. No signing, no storage, no crypto."

**Severity: blocker.** The diagram truthfully represents the shipped code but contradicts the central positioning claim that "signing keys live outside the agent."

---

### Finding 2.2 — "cryptographic receipts" feature claim without daemon caveat (drift)

**Site claim:** `mcp-proxy/overview.mdx` line 24: "**Cryptographic receipts** -- Ed25519-signed W3C Verifiable Credentials, hash-chained per session."

**Problem:** This claim is technically accurate for the current implementation but creates an implied trust guarantee. The pitch.md differentiation statement ("A compromised agent cannot forge or suppress its own receipts") only holds once the daemon split lands. Listing cryptographic receipts as a feature without noting that the key lives in-process with the proxy positions this as equivalent to the future daemon model when it is not.

**Ground truth:** ADR-0010 Context: current architecture means "every emitter… currently carries its own copy of the keypair in memory."

**Severity: drift.**

---

### Finding 2.3 — `-key private.pem` usage presented as correct operator pattern (drift)

**Site claim:** `mcp-proxy/overview.mdx` lines 63–67 and 79–94. The overview and quick-start both show `-key /Users/YOU/.agent-receipts/github-proxy.pem` as the recommended way to use a persistent signing key, with the key file living in a user home directory path owned by the same user running the agent client.

**Problem:** Under ADR-0010, the private key must live exclusively in the daemon process as a separate OS user. The current pattern of passing a key file to a proxy binary that runs as the same user as the agent does not provide the isolation the positioning claims. Operators following this documentation will have a key arrangement that has no isolation boundary between agent and signer.

**Ground truth:** ADR-0010 Permissions and trust: "Daemon is the sole writer to the database and key store. Emitters cannot read the database or keys."

**Severity: drift.** This is the current supported workflow; the documentation correctly describes it. The drift is that no caveat is given explaining that this arrangement does not provide the daemon-isolation property advertised in the positioning.

---

## 3. `site/src/content/docs/mcp-proxy/installation.mdx` — MCP Proxy Installation

### Finding 3.1 — "generates an ephemeral Ed25519 key pair for signing receipts" (drift)

**Site claim:** `mcp-proxy/installation.mdx` line 52: "By default it generates an ephemeral Ed25519 key pair for signing receipts."

**Problem:** The key generation happens in the proxy process itself (`main.go` lines 196–202: `receipt.GenerateKeyPair()` called in the proxy's `main`). This accurately describes the code but is architecturally inconsistent with the positioning that keys live outside the agent. The proxy is a child process of the MCP client; the key lives in the same process tree as the agent.

**Ground truth:** ADR-0010 Decision: daemon is "sole owner of the signing keys."

**Severity: drift.**

---

### Finding 3.2 — "Persistent signing key" section (drift)

**Site claim:** `mcp-proxy/installation.mdx` lines 69–80. The section titled "Persistent signing key" instructs users to generate a key with `openssl genpkey -algorithm Ed25519 -out private.pem` and run the proxy with `-key private.pem`. The key is stored as a file accessible to the same user session running the proxy.

**Problem:** Same key-ownership problem as Finding 2.3. No mention that this does not achieve the daemon-isolation guarantee.

**Severity: drift.**

---

## 4. `site/src/content/docs/openclaw/overview.mdx` — OpenClaw Overview

### Finding 4.1 — "Signs a W3C Verifiable Credential receipt with an Ed25519 key" (blocker)

**Site claim:** `openclaw/overview.mdx` lines 16 and 37–43. The "What it does" list includes "Signs a W3C Verifiable Credential receipt with an Ed25519 key." The flow diagram explicitly labels the `after_tool_call` hook step as "sign receipt (Ed25519)." The key is described as living at `~/.openclaw/agent-receipts/keys.json`.

**Problem:** The OpenClaw plugin runs inside the OpenClaw agent process. The signing key is stored in the agent's own home directory and held in the agent process memory. This is the exact topology ADR-0010 calls "not a meaningful audit": "a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts." Under ADR-0010, the plugin should become a thin emitter with no key; the daemon does the signing.

**Ground truth:** ADR-0010 Decision: "`@agnt-rcpt/openclaw`… become[s] v2 with the daemon as a runtime requirement." ADR-0010 Schema split: "Emitter sends the minimum faithful representation… No signing, no storage, no crypto."

**Severity: blocker.** The OpenClaw plugin explicitly signs receipts in-process within the agent being audited — the architecturally broken state that ADR-0010 was written to fix — and the overview presents this as the correct design without caveat.

---

### Finding 4.2 — "so the agent can query and verify its own audit trail" (drift)

**Site claim:** `openclaw/overview.mdx` line 19: "Exposes two agent tools (`ar_query_receipts`, `ar_verify_chain`) so the agent can query and verify its own audit trail."

**Problem:** Under the daemon model, reads happen via direct SQLite access with filesystem permissions (ADR-0010 Read interface) — the agent can read but cannot write. Under the current in-process model, the agent holds the signing key, writes to the database, and also reads from it, meaning there is no independent verification: the agent is verifying receipts it could have forged. The phrasing "verify its own audit trail" normalises self-verification, which is architecturally meaningful only after the daemon split separates the write path.

**Ground truth:** ADR-0010 Consequences (Positive): "Restores the audit property: an agent cannot forge, suppress, or tamper with its own receipts."

**Severity: drift.**

---

## 5. `site/src/content/docs/openclaw/installation.mdx` — OpenClaw Installation

### Finding 5.1 — `keyPath` configuration option (drift)

**Site claim:** `openclaw/installation.mdx` lines 72–75:
```json
"keyPath": "~/.openclaw/agent-receipts/keys.json"
```
The configuration shows the signing key path as a plugin-level configuration option, with a default that places it inside the user's home directory (same user as the agent).

**Problem:** Under ADR-0010, there is no `keyPath` for the emitter — the emitter has no key. Configuring where the emitter's key lives is a concept that only exists under the in-process architecture.

**Ground truth:** ADR-0010 Decision: thin emitter has "No signing, no storage, no crypto."

**Severity: drift.** Accurately documents current shipped config; the drift is that this configuration concept has no place in the target architecture.

---

## 6. `site/src/content/docs/blog/openclaw-plugin-deep-dive.mdx` — OpenClaw Blog Post

### Finding 6.1 — "To tamper with the chain, you'd need to… re-sign every receipt with the private key. Without the key, the chain is tamper-evident" (blocker)

**Site claim:** `blog/openclaw-plugin-deep-dive.mdx` lines 143–145:

> "To tamper with the chain, you'd need to modify a receipt, recompute all subsequent hashes, and re-sign every receipt with the private key. Without the key, the chain is tamper-evident."

**Problem:** This claim implies that the private key provides the tamper-evidence guarantee. Under the current architecture, the private key lives at `~/.openclaw/agent-receipts/keys.json` and is loaded into the OpenClaw agent process. A compromised agent process has access to the key file path configured in its own `openclaw.json` and can re-sign forged receipts. The tamper-evidence claim depends on the daemon model (key held exclusively by a separate process/OS user) — it does not hold in the current in-process implementation.

**Ground truth:** ADR-0010 Context: "A compromised or misbehaving agent can forge, suppress, or tamper with its own receipts." pitch.md Differentiation: "A compromised agent cannot forge or suppress its own receipts" — this is listed as a future/positioning goal, not the current state.

**Severity: blocker.** This is an explicit trust-model claim that is false under the current shipped architecture.

---

### Finding 6.2 — `parameterPreview` (deprecated name) used throughout the blog post (nit)

**Site claim:** `blog/openclaw-plugin-deep-dive.mdx` lines 162–196. The blog post uses `parameterPreview` / `parameters_preview` throughout.

**Problem:** `openclaw/installation.mdx` line 83 documents the renamed field as `parameterDisclosure` / `parameters_disclosure` per ADR-0012, and explicitly states "There is no deprecation alias — update your `openclaw.json`." The blog post uses the old names without noting the rename.

**Severity: nit.** This is a documentation consistency issue, not an architectural one, but it will confuse readers who follow the blog post after reading the installation guide.

---

## 7. `site/src/content/docs/getting-started/quick-start.mdx` — Quick Start

### Finding 7.1 — SDK quick start shows caller-owned key pair (drift)

**Site claim:** `getting-started/quick-start.mdx` lines 20–44 (TypeScript), lines 85–113 (Python). Both examples call `generateKeyPair()` / `generate_key_pair()` in the calling process and pass the resulting private key to `signReceipt()` / `sign_receipt()`.

**Problem:** Under ADR-0010, SDK consumers become thin emitters with no signing keys. The quick-start demonstrates and normalises in-process key ownership. A developer following this guide will build an application that holds its own signing key — the pattern ADR-0010 deprecates and removes.

**Ground truth:** ADR-0010 Decision: "v1 in-process behaviour is deprecated and removed rather than left available, because shipping the 'agent signs its own receipts' footgun under the agent-receipts name is worse than a major version bump."

**Severity: drift.** The quick-start accurately shows current SDK v1 behaviour. The drift is that it teaches a pattern that will be a hard breaking change at v2 with no forward-looking caveat.

---

## 8. `site/src/content/docs/specification/overview.mdx` — Specification Overview

### Finding 8.1 — "Issuer" definition does not acknowledge process-separation requirement (drift)

**Site claim:** `specification/overview.mdx` lines 96–98:

> "The agent (or agent platform) that performed the action and produced the receipt. The issuer signs the receipt with its private key."

**Problem:** "The issuer signs the receipt with its private key" implies the issuer (agent) holds the private key. Under ADR-0010, the issuer identity is supplied by the emitter (agent) but the signing key lives in the daemon. The agent/issuer does not hold or use a private key in the target architecture.

**Ground truth:** ADR-0010 Decision: daemon "sole owner of the signing keys." Schema split: the emitter supplies `session_id`, `channel`, `tool`, `input`, `output` — no crypto.

**Severity: drift.**

---

## 9. `site/src/content/docs/specification/how-it-works.mdx` — How It Works

### Finding 9.1 — Signing flow diagram attributes signing to the issuer without process context (drift)

**Site claim:** `specification/how-it-works.mdx` lines 58–90. The signing flow SVG and accompanying text describes: "Sign the canonical bytes with the issuer's **Ed25519** private key." No process boundary is shown; the signing is presented as a step the issuer (agent) performs.

**Problem:** Same as Finding 8.1. Under ADR-0010, "issuer's private key" is held exclusively by the daemon, not by the issuer process. The diagram and text give no indication that the signing step occurs in a separate process.

**Severity: drift.**

---

## 10. `site/src/content/docs/ecosystem/index.mdx` — Ecosystem / Landscape

### Finding 10.1 — Agent Receipts' own trust model characterised only as "Same-process proxy" for mcp-firewall but the landscape page does not characterise Agent Receipts' own trust model (nit)

**Site claim:** `ecosystem/index.mdx` lines 45: The comparison table column for trust model shows other tools as "Same-process middleware," "Capability separation (proxy has no secrets)," etc. Agent Receipts is not included as a row in this table (it is the author), but the positioning in the surrounding text does not note that Agent Receipts currently also uses a same-process model.

**Problem:** The landscape description for Pipelock reads "Capability separation (proxy has no secrets)." By contrast, Agent Receipts' current MCP proxy holds secrets (signing key). The differentiation this page implies for Agent Receipts relative to "same-process middleware" is not yet structurally realised.

**Severity: nit.** Agent Receipts is not compared directly in the table, so this is an omission rather than a false claim.

---

## 11. `site/src/content/docs/openclaw/agent-tools.mdx` — Agent Tools

### Finding 11.1 — "A valid chain guarantees that no receipt was altered, inserted, or deleted after it was written" (blocker)

**Site claim:** `openclaw/agent-tools.mdx` lines 89–91:

> "A valid chain guarantees that no receipt was altered, inserted, or deleted after it was written. If the chain is broken, treat all receipts from the reported position onward as potentially compromised."

**Problem:** Under the current in-process architecture, the agent process holds the signing key. A valid chain does not guarantee the agent did not forge receipts — it only guarantees the receipts were signed with the key that is stored in the agent's own config directory. A valid chain produced by an in-process signer provides integrity within the session but not independence from the agent. The stated guarantee ("no receipt was altered, inserted, or deleted") is only meaningful when the key lives in a separate process (daemon model), where the agent cannot forge new signed receipts.

**Ground truth:** ADR-0010 Context: "An agent auditing itself is not a meaningful audit."

**Severity: blocker.**

---

## Cross-cutting Issues

### CC-1 — The "agent cannot forge its own receipts" claim is asserted before the enabling architecture is shipped (blocker pattern)

Multiple pages either state or imply that Agent Receipts provides a tamper-evident trail the agent cannot forge:
- `index.mdx`: "tamper-evident" without process-isolation caveat
- `openclaw/overview.mdx`: positions in-process signing as the implementation of this claim
- `blog/openclaw-plugin-deep-dive.mdx` lines 143–145: explicit tamper-evidence claim dependent on key isolation
- `openclaw/agent-tools.mdx` lines 89–91: "a valid chain guarantees…"

The pitch.md states this guarantee requires the daemon (ADR-0010). ADR-0010 is Proposed, not shipped. The code confirms in-process signing throughout. Every tamper-evidence claim that depends on key isolation is currently overstated.

### CC-2 — Every integration is shown as owning its own keys (blocker pattern)

Three separate key-ownership patterns appear across the site, all in-process:
- MCP proxy: `-key private.pem` flag, key in proxy process (`main.go:194`)
- OpenClaw plugin: `keyPath: ~/.openclaw/agent-receipts/keys.json`, key in plugin process
- SDK: `generateKeyPair()` called by the SDK consumer

ADR-0010 Decision describes this multi-key-owner problem explicitly: "every emitter… currently carries its own copy of the keypair in memory… Running multiple MCP proxies plus an agent session means N independent crypto/storage stacks doing the same job, with N separate chains." The site presents this N-key topology as the correct design with no indication it is the known-broken state.

### CC-3 — No page acknowledges ADR-0010 or the planned architectural transition (drift)

The site has no page, callout, or note that:
- The current architecture is in-process (v1)
- The daemon separation is planned (ADR-0010)
- v2 will be a hard breaking change for all emitters

Users building against the current SDKs or proxy will be surprised by a major breaking change with no advance notice from the docs. The pitch.md already treats the daemon model as the current value proposition ("Install the daemon" is the primary CTA), creating a gap between what the docs teach and what the marketing promises.

### CC-4 — `specification/how-it-works.mdx` and `specification/overview.mdx` SVG diagrams show signing as an issuer-owned operation with no daemon node (drift)

Both specification pages contain SVG flow diagrams showing the signing pipeline: Receipt fields → RFC 8785 canonicalize → Ed25519 sign → Signed Receipt. Neither diagram includes a daemon or process-boundary concept. Under ADR-0010, RFC 8785 canonicalization and Ed25519 signing both move exclusively to the daemon. The specification diagrams depict the signing step as something that "just happens" with no indication of who owns the key or in which process, which is consistent with either architecture — but given the absence of any daemon concept anywhere on the site, readers will infer in-process.
