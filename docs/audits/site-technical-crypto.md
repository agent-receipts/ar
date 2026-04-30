# Site Technical Audit — Cryptographic and Protocol Accuracy

**Scope:** Cryptographic primitives and protocol-level claims on the agentreceipts.ai site.  
**Out of scope:** Daemon architecture, SDK install/version details.  
**Ground truth sources:** ADR-0001 through ADR-0003, ADR-0007 through ADR-0009, ADR-0012; `spec/schema/agent-receipt.schema.json`.  
**Date:** 2026-04-30

---

## 1. `proofValue` encoding — z-prefix base58btc vs u-prefix base64url

This is the most pervasive finding. ADR-0001 §Encoding commits the protocol to **multibase base64url with `u` prefix** (no padding). The JSON schema at `spec/schema/agent-receipt.schema.json` lines 408–412 enforces this with the regex pattern `^u[A-Za-z0-9_-]{86}$` and the description "Multibase-encoded (u-prefixed base64url, no padding)". ADR-0003 §Deviations explicitly calls out that the schema previously had a `z`-prefix inconsistency and states the `u`-prefix base64url encoding defined in ADR-0001 is authoritative.

Despite the schema and ADR being aligned on `u`-prefix, the following site pages still describe `z`-prefixed base58btc:

### 1a. `specification/how-it-works.mdx`

- **Site claim (SVG label, line 79):** `"z-base58btc"` (rendered as a step label in the signing flow diagram)
- **Site claim (prose, line 89):** `"Encode the signature as **z-prefixed base58btc** and attach as `proof.proofValue`"`
- **Ground truth:** ADR-0001 §Encoding; schema `spec/schema/agent-receipt.schema.json` lines 408–412
- **Severity: blocker** — the encoding is wrong and contradicts the deployed schema pattern. A reader implementing from this page would produce a `z`-prefixed base58btc value that the schema rejects.

### 1b. `specification/receipt-chain-verification.mdx`

- **Site claim (SVG label, line 30):** `"z-base58btc"`
- **Site claim (prose, line 55):** `"The issuer signs the canonical receipt (proof field excluded) with its Ed25519 private key. The signature is encoded as a multibase string (`z`-prefixed base58btc) and placed in `proof.proofValue`."`
- **Ground truth:** ADR-0001 §Encoding; schema lines 408–412
- **Severity: blocker** — same as 1a. This is the canonical verification algorithm page; the encoding claim is incorrect throughout.

### 1c. `specification/agent-receipt-schema.mdx`

- **Site claim (example JSON, line 126):** `"proofValue": "z..."` — the placeholder starts with `z`
- **Site claim (proof table, line 235):** `"Multibase-encoded (`z`-prefixed base58btc) Ed25519 signature."`
- **Ground truth:** ADR-0001 §Encoding; schema lines 408–412
- **Severity: blocker** — the schema reference page itself contradicts the schema. The placeholder `"z..."` and the table description both assert base58btc. The actual schema requires `u`-prefixed base64url. Note: the blog post at `blog/openclaw-plugin-deep-dive.mdx` line 118 shows a real receipt with a `u`-prefixed value (`"proofValue": "usxX8..."`) — this example is correct and contradicts the three spec pages above.

---

## 2. Disclosure field name and architecture — `parameterPreview` vs `parameterDisclosure`

ADR-0012 §Naming renames the config knob from `parameterPreview` to `parameterDisclosure` and the receipt field from `parameters_preview` to `parameters_disclosure`. ADR-0012 also states the plaintext-in-body mode is removed in favour of asymmetric encryption via a structured envelope.

### 2a. `blog/openclaw-plugin-deep-dive.mdx`

- **Site claim (line 156):** Section heading: `"## parameterPreview: operator-controlled privacy"`
- **Site claim (line 160):** `"If you need more forensic detail, set `parameterPreview` in `openclaw.json`"`
- **Site claim (line 168):** Config example using `"parameterPreview": "high"`
- **Site claim (line 176):** `"With `parameterPreview: "high"`, high-risk and critical actions include a `parameters_preview` field alongside the hash:"`
- **Site claim (lines 183–188):** Receipt example showing `"parameters_preview": { "command": "..." }` — a plaintext field in the signed receipt body
- **Site claim (line 226):** `"Even with `parameterPreview: true`, what's stored is a best-effort plaintext representation, not the full canonical arguments object."`
- **Ground truth:** ADR-0012 §Naming commits to `parameterDisclosure` / `parameters_disclosure`; §Alternatives Considered explicitly rejects "Plaintext-in-body (TS SDK today)" as "superseded by encrypted-in-body"; ADR-0012 §Consequences states "`parameters_preview` field is repurposed ... plaintext-in-body is removed as a supported mode"
- **Severity: drift** — the blog post describes an architecture (plaintext field in the signed body, `parameterPreview` config key) that ADR-0012 has deprecated. The post predates ADR-0012 but is not gated with a caveat. The JSON example with `"parameters_preview"` showing plaintext in a signed receipt contradicts the privacy model the spec intends.

---

## 3. Schema version claim — site shows `0.1.0` only

### 3a. `specification/agent-receipt-schema.mdx`

- **Site claim (version table, line 140):** `"version" | Yes | Spec version. Must be "0.1.0" for this version.`
- **Site claim (example JSON, line 53):** `"version": "0.1.0"`
- **Ground truth:** `spec/schema/agent-receipt.schema.json` line 45: `"enum": ["0.1.0", "0.2.0", "0.2.1"]` — the schema already accepts three versions. ADR-0008 introduced `0.2.0` (response hashing, terminal marker). ADR-0009 introduced `0.2.1` (null-field rule, `issuanceDate` commitment).
- **Severity: drift** — the schema page pins the version to `0.1.0` and omits `response_hash` (ADR-0008), `chain.terminal` (ADR-0008), and the null-field canonicalization rule (ADR-0009). The spec itself is multi-version; the site presents only v0.1.0.

### 3b. `specification/overview.mdx`

- **Site claim (badge, line 8):** `<Badge text="v0.1.0" variant="note" />`
- **Ground truth:** Current schema version is `0.2.1`; the protocol has shipped `response_hash` and `chain.terminal` under versions `0.2.0`/`0.2.1`.
- **Severity: drift** — the overview badge is two minor versions behind.

---

## 4. DID resolution — chain verification step glosses over the unresolved gap

### 4a. `specification/receipt-chain-verification.mdx`

- **Site claim (line 63):** `"Verify the `proof` signature against the issuer's public key at `proof.verificationMethod`."`
- **Ground truth:** ADR-0003 §Security Considerations: "`verificationMethod` field contains a DID URL ... DID resolution — the process of resolving this URL to an actual public key — is not specified in v0.1 of the protocol (see spec 9.6). Verifiers must currently obtain public keys through out-of-band means." ADR-0007 is in Proposed status with no decision; `did:agent:` DIDs used in examples have no defined resolution mechanism.
- **Severity: drift** — the site presents verification step 2a as a self-contained instruction ("verify signature against the issuer's public key at `proof.verificationMethod`") with no caveat that the DID-to-key resolution step is unspecified and must be done out of band. A reader implementing a verifier would not know that key lookup is an open protocol gap.

### 4b. `specification/agent-receipt-schema.mdx`

- **Site claim (example JSON, line 124):** `"verificationMethod": "did:agent:claude-cowork-instance-abc123#key-1"` — uses `did:agent:` which is an illustrative placeholder with no defined resolution mechanism
- **Ground truth:** ADR-0007 §Context: "`did:agent:` ... are illustrative placeholders with no defined resolution mechanism"; ADR-0007 §Consequences: "Existing examples and test vectors using `did:agent:` identifiers will need updating once a decision is finalized."
- **Severity: nit** — using `did:agent:` in examples is noted as pending update by the ADR itself, but the example appears without any caveat that the method is a placeholder.

---

## 5. Canonicalization — correct algorithm, incomplete description of deviation

### 5a. `specification/receipt-chain-verification.mdx`

- **Site claim (line 51):** `"This approach aligns with the W3C Verifiable Credentials Data Integrity specification, though the signing procedure defined here is intentionally simplified."`
- **Ground truth:** ADR-0002 §Known Risks is explicit: "Not the W3C VC Data Integrity default. The W3C VC Data Integrity specification uses JSON-LD canonicalization (RDF Dataset Canonicalization) as its primary method. By choosing RFC 8785, Agent Receipts diverge from tooling that assumes JSON-LD processing." ADR-0003 §Deviations lists this as deviation #1, noting RFC 8785 is used "rather than JSON-LD canonicalization (URDNA2015)".
- **Severity: nit** — the site says "aligns with" the W3C VC Data Integrity spec, which understates the deviation. The canonicalization method is different (RFC 8785 vs URDNA2015), not merely "simplified". The phrase risks misleading implementers who expect standard W3C Data Integrity tooling to work.

---

## 6. Chain truncation — no mention of detection limits

### 6a. `specification/receipt-chain-verification.mdx`

- **Site claim (lines 59–69):** The chain verification algorithm is presented as five steps with no caveat about tail truncation.
- **Ground truth:** ADR-0008 §2 mandates a normative subsection in spec §7.3 stating "chain verification does not detect tail truncation" and requires SDK docstrings to mirror this language. ADR-0008 §Security Considerations §"Truncation detection has a floor" is explicit: "No mechanism can detect truncation of receipts that never existed." The `ExpectedLength`/`ExpectedFinalHash` verifier parameters (ADR-0008 §3) and `chain.terminal`/`RequireTerminal` (ADR-0008 §4) are also absent from the site.
- **Severity: drift** — the site presents chain verification as complete without disclosing the known truncation-detection gap or the out-of-band mitigation parameters. Security-conscious readers designing audit systems need this information.

---

## 7. Privacy/disclosure — spec overview principle vs ADR-0012 architecture

### 7a. `specification/overview.mdx`

- **Site claim (line 12–13):** `"Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed. Sensitive data never appears in receipts — only hashes and user-controlled previews."`
- **Ground truth:** ADR-0012 §Forces in tension notes that "hash-only receipts can prove tampering but cannot answer 'what command ran?'" and introduces `parameters_disclosure` as an asymmetrically encrypted in-body field. ADR-0012 rejects plaintext previews. The phrase "user-controlled previews" echoes the old `parameterPreview`/`parameters_preview` design that ADR-0012 explicitly rejects. Under the current architecture, disclosures are operator-controlled (not user-controlled per ADR-0012 §Operator control: "MUST live in operator config ... never in agent-supplied input") and encrypted, not plaintext previews.
- **Severity: drift** — "user-controlled previews" misattributes the control party (should be operator) and implies a plaintext preview mode that ADR-0012 removes. "Sensitive data never appears in receipts" is accurate for the hash-only default but potentially misleading if `parameters_disclosure` (encrypted ciphertext) is present in the signed receipt body.

### 7b. `index.mdx`

- **Site claim (line 132–133):** `"Parameters are hashed, not stored in plaintext. The human principal controls what is disclosed. Sensitive data never appears in receipts."`
- **Ground truth:** Same as 7a. The control party is the operator, not the human principal.
- **Severity: drift** — same issue as 7a, repeated on the landing page.

---

## 8. Standards reuse claim — correctly stated

The pitch document (`docs/positioning/pitch.md` line 58) states: "Not a competing standard. Receipts use the same Ed25519 and SHA-256 primitives the rest of the space converged on, wrapped in the W3C Verifiable Credentials envelope. We are reusing standards, not authoring a new one." The site's `specification/overview.mdx` (line 16) and `index.mdx` (line 136) accurately echo this: "Built on existing standards … No novel cryptographic primitives." No "competing standard" residue found. This claim is correct.

---

## 9. VC envelope — mostly correct, one field-name nit

### 9a. `specification/overview.mdx` and `specification/how-it-works.mdx`

- Both pages consistently show `issuanceDate` in diagrams (lines 40 and 21 respectively), which is correct per ADR-0009.
- No use of `validFrom` found on any site page. Correct.

### 9b. `specification/agent-receipt-schema.mdx`

- **Site claim (line 140):** Lists `issuanceDate` as a required field. Correct per ADR-0009.
- No deviation found from ADR-0003's field-name commitment.

### 9c. VC features out of scope

The site does not claim `credentialStatus`, `holder`, JSON-LD processing, or other out-of-scope VC features are implemented. The `@context` description on the schema page (line 135) accurately calls it a "JSON-LD context" without claiming it is dereferenced. No issues found here.

---

## 10. Hash algorithm — correct throughout

All pages consistently describe SHA-256 for chain hashing and `sha256:` prefixes for all hash fields. No mention of alternative hash algorithms. The ADR-0008 claim that SHA-256 is used for `response_hash` is not mentioned on the site (as noted under finding 6), but no wrong algorithm is stated. No issue.

---

## Cross-Cutting Issues

### A. `proofValue` encoding is wrong in all three spec pages

Findings 1a, 1b, and 1c all describe `z`-prefixed base58btc. The JSON schema, ADR-0001, and ADR-0003 all commit to `u`-prefix base64url. The blog post (finding in section 1c) shows a real receipt with a `u`-prefix value, creating an internal contradiction on the site. This is the highest-priority finding because it is a blocker-level implementation error on the pages most likely to be read by integrators.

The pattern: three specification pages were written before ADR-0003 §Deviation #3 was closed, and none were updated when the schema was corrected.

### B. Site version coherence — content written against v0.1.0, schema is v0.2.1

The specification pages (overview badge, schema page version table, schema example) describe v0.1.0. The actual schema file accepts v0.1.0, v0.2.0, and v0.2.1 and has fields (`response_hash`, `chain.terminal`) absent from the site documentation. ADR-0008 and ADR-0009 changes are fully absent from the site.

### C. ADR-0012 disclosure architecture not reflected

The blog post, specification overview, and landing page all describe a disclosure model (`parameterPreview`, `parameters_preview`, plaintext-in-body, "user-controlled") that ADR-0012 supersedes. ADR-0012 is in Proposed status, but its architecture is committed (the receipt format is permanent once signed) and the old field names/semantics are explicitly deprecated.

### D. DID resolution gap not surfaced on verification page

The chain verification page presents a verification algorithm that includes key lookup via `proof.verificationMethod` without disclosing that DID resolution is unspecified (ADR-0007 is Proposed, not Accepted; `did:agent:` has no resolver). This gap is non-trivial for anyone building an independent verifier.
