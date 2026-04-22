# ADR-0008: Response Hashing and Chain Completeness

## Status

Accepted

## Context

Two independent gaps in the current receipt model (v0.1.0) motivate this ADR. The initial framing was that bundling them would let the protocol migrate from `0.1.0` once. Working through the chain-completeness mechanism closely (see §"Why in-chain truncation detection does not work" below) showed that the only in-chain designs either restate information already in the schema or require a substantially bigger protocol change than a single optional field. The schema-bump-once rationale therefore collapses for that piece: the right companion to response hashing is a non-schema caller-supplied verification parameter, not another field.

**Gap 1 — Receipts hash the request but not the response (#153).** The `credentialSubject.action.parameters_hash` field (see spec §4.3.2, [agent-receipt.schema.json#L158](../../spec/schema/agent-receipt.schema.json#L158)) captures what the agent asked. The `outcome` block captures status and result metadata but not a cryptographic commitment to the server's response body. A compromised MCP server, a tampering proxy, or an incident investigator cannot distinguish a legitimate response from a modified one from the receipt alone. The receipt chain proves intent but not outcome.

**Gap 2 — Chain verification does not detect tail truncation (#171).** The SDK verifiers in [sdk/go/receipt/chain.go](../../sdk/go/receipt/chain.go), [sdk/ts/src/receipt/chain.ts](../../sdk/ts/src/receipt/chain.ts), and [sdk/py/src/agent_receipts/receipt/chain.py](../../sdk/py/src/agent_receipts/receipt/chain.py) check signatures, hash linkage, and strict sequence increment. Dropping the last N receipts from a chain still verifies as `Valid: true` because there is no anchor for "this chain is complete". Mid-chain deletion is caught; tail truncation is not.

### Why in-chain truncation detection does not work

Before enumerating options, a cryptographic floor: no purely in-chain commitment can detect truncation of receipts that do not yet exist at signing time. A receipt can only commit to values its issuer already knows.

| What an in-chain field could commit to | Detects tail truncation? |
|---|---|
| "Current length at this receipt" | No — equivalent to `sequence`, already present |
| "Expected final length" | Only if the issuer knows its end state at sign time, which open-ended agents do not |
| "Hash of final receipt" | Same constraint — unknowable mid-chain |
| "Hash of the next receipt" | Requires delaying signing until the next action is chosen; still leaves the last signed receipt unprotected |
| Merkle accumulator of prior receipts | Detects prior-receipt deletion (already covered by hash chaining); does nothing for the tail |

The only mechanisms that genuinely detect tail truncation are (a) an external witness supplied at verification time (expected length or final hash), or (b) a closure ceremony — a terminal-marker receipt, useful only for chains with a defined lifecycle and noisy for long-running agents. Anything in-chain that goes beyond these is effectively a transparency-log protocol — substantially larger than a single field.

### Options considered

- **Option A: Documentation-only (the minimal #171).** Update the spec §7.3 to state explicitly that chain verification does not detect tail truncation, mirror that language in the three SDK verifier docstrings, and add per-SDK tests that pin `Valid: true` for a truncated chain so future maintainers cannot silently tighten verification without a spec change. No schema change. Honest about current behaviour but provides no mitigation on its own.

- **Option B: Out-of-band commitment (verifier parameters).** Extend each SDK's `VerifyChain` API with optional `ExpectedLength` and/or `ExpectedFinalHash` parameters. Callers who know — through an external mechanism such as an audit log, a signed checkpoint, or a published transparency record — what the chain's final state should be, pass that in and the verifier fails if the observed chain does not match. No schema change; no per-receipt overhead. The cost is pushed to the caller: they must obtain the expected value out of band. This is the only mechanism that actually works for open-ended chains, and it composes cleanly with Option A (callers who cannot supply external state still get the `Valid: true` signal today, but now with documented caveats).

- **Option C (rejected): In-chain length commitment schema field.** An earlier draft of this ADR proposed adding an optional `credentialSubject.chain.length_commitment` field signed into each receipt. On closer analysis, see the table above: every concrete interpretation of such a field either duplicates `sequence`, requires knowledge the issuer does not have, or reduces to a transparency-log protocol. The ADR rejects this option as security theatre. If in-chain truncation detection is pursued in the future, it needs a purpose-designed ADR covering checkpoint receipts, external anchoring, and the accompanying verifier state — not a single hand-wavy field.

- **Option D: Terminal-marker receipt.** Add a `chain.terminal: true` flag to mark the final receipt in a chain. Verifiers flag any chain whose last observed receipt is not marked terminal as "possibly truncated". Self-contained and simple, but requires every chain to be explicitly closed. Agents that crash, are killed, or are long-running never close their chains, so in practice most chains would verify as "possibly truncated" and the signal would be noise. Useful for chains with a defined lifecycle (single agent runs) but not a general-purpose mechanism. Deferred to a future ADR alongside any transparency-log work.

Related: #153, #171, spec §7.3 (chain integrity verification), spec §9.3 (open question on receipt tampering), ADR-0002 (RFC 8785 canonicalization), ADR-0003 (VC envelope format).

## Decision

*Both sub-decisions below are concrete and intended for immediate implementation. The open questions listed at the end are for community input on details, not on the overall shape.*

The release that closes #153 and the documentation portion of #171 ships three things together:

1. §1 — response hashing (schema change, `0.2.0`).
2. §2 — Option A: documentation + pinning tests for chain truncation (no schema change).
3. §3 — Option B: optional verifier parameters for out-of-band truncation detection (no schema change).

Options C (in-chain length commitment field) and D (terminal-marker receipt) are rejected at this layer and deferred to a potential future ADR on transparency-log-style checkpointing.

### 1. Response hashing (from #153)

Add an optional field `credentialSubject.outcome.response_hash` containing the SHA-256 hash of the RFC 8785 canonical JSON of the server's response, computed **after** secret redaction.

- **Field name and location.** `outcome.response_hash`, same shape as the existing `parameters_hash` (`$ref: "#/$defs/sha256Hash"`).
- **Canonicalization.** RFC 8785 over the redacted response body, identical to the rules already in force for the receipt envelope (ADR-0002).
- **Ordering.** Redact → hash response → populate `outcome` → sign receipt. Non-negotiable: a hash computed before redaction does not match the record anyone can ever replay, which defeats the purpose.
- **Optional field.** Receipts without `response_hash` remain valid. Verifiers validate the hash *when present* and treat absence as "the issuer did not commit to the response"; they do not fail. This preserves backwards compatibility with `0.1.0` receipts.
- **Storage.** Hash only. Full responses are not stored in the receipt. MCP responses can be megabytes (`get_file_contents`, search results); inlining would balloon receipt size and leak data by default.
- **Verifier behaviour.** `mcp-proxy verify` and the three SDK verifiers recompute the hash when the response is available (e.g., during an integration test or a replay) and fail if it does not match. When the response is not available, they note "response hash present, response body not supplied" and continue.

Schema bumps from `0.1.0` to `0.2.0`. Verifiers must accept both.

### 2. Documentation of truncation detection limits (Option A, from #171)

Add a normative subsection to spec §7.3 stating that chain verification does not detect tail truncation. Mirror that language in the `VerifyChain` godoc, TSDoc, and docstring in the three SDKs. Add a test per SDK that constructs a chain, drops the last N receipts, and asserts the result is still `Valid: true`. These tests pin the property so a future maintainer cannot silently tighten verification without a spec change and ADR update.

This is no-cost honesty about the current guarantee and a necessary precondition for §3 — callers cannot reason about the out-of-band verifier parameters without understanding why they exist.

### 3. Out-of-band truncation detection (Option B, from #171 follow-up)

Extend each SDK's chain-verification API with optional parameters:

- `ExpectedLength` (integer) — if supplied, verification fails when the observed chain length does not equal this value.
- `ExpectedFinalHash` (hash) — if supplied, verification fails when the hash of the last observed receipt does not equal this value.

Both parameters are optional and default to unset (current behaviour). No schema change. Callers who maintain an external record of chain state (audit log, transparency log, signed checkpoint) can pass these in and detect truncation; callers who do not are no worse off than today.

The exact parameter names and idiomatic surface differ per SDK (`ExpectedLength`/`ExpectedFinalHash` in Go; `expectedLength`/`expectedFinalHash` options object in TS; `expected_length=`/`expected_final_hash=` kwargs in Python) but the semantics are shared and covered by cross-SDK test vectors.

This is the concrete mitigation the original #171 follow-up gestured at, landed now.

### Open questions for community input

- **Does response hashing need to be mandatory at some future version?** Leaving it optional forever weakens the guarantee for compliance use cases. A future minor version could require it.
- **Redaction determinism across SDKs.** RFC 8785 is stable, but the redaction step is SDK-specific. Do all three SDKs produce byte-identical redacted responses for the same input? If not, `response_hash` verification will fail cross-SDK. This must be nailed down in the spec and covered by shared test vectors.
- **What does `response_hash` mean for streaming responses?** MCP does not currently stream tool results, but if it does in the future, hashing the full response is not possible without buffering.
- **Is there a near-term need for in-chain truncation detection (transparency-log / checkpoint design)?** §3 covers callers with external state. Callers without it still have no in-band detection. Before investing in a larger protocol change, we want signal on whether real deployments need it.

## Security Considerations

### Redaction before hashing is load-bearing

If response hashing happens before secret redaction, the hash commits to a value that is never stored or shared — so verification always fails, or worse, the raw response is shipped to verifiers to make hashes match, defeating redaction. The ordering rule (redact → hash → sign) must be specified in the spec and enforced by per-SDK tests with a known secret in a known response.

### Response hash ≠ response integrity across the wire

`response_hash` commits the issuer to a particular response at the time of receipt creation. It does not protect against an attacker who controls the issuer at receipt-creation time — such an attacker can compute any hash they want. The protection is against post-hoc tampering (modified receipts, replayed responses, compromised archival storage) and against downstream parties who alter their copy of the response.

### Truncation detection has a floor

No in-band mechanism can detect truncation of receipts that did not exist when the last observed receipt was signed. A receipt only commits to values its issuer already knows; it cannot commit to its own successors. §3 (Option B) is therefore the only mechanism in this ADR that actually detects tail truncation, and it does so by pushing the commitment out of band. Callers without access to an external witness have no in-band detection — the spec must state this explicitly so operators understand what the protocol does and does not guarantee.

### Schema version as a security signal

Bumping the schema version to `0.2.0` is itself a security communication: verifiers that see `0.1.0` receipts know the response-hashing guarantee is absent. Verifiers that see `0.2.0` receipts with a missing `response_hash` know the issuer chose not to hash the response, which may be a policy violation. The spec must make these states distinguishable and meaningful.

### Hash collisions and algorithm agility

SHA-256 is consistent with existing hashes in the schema. No algorithm change is proposed here. If a future ADR moves to SHA-3 or another family, the schema will need algorithm agility in both `parameters_hash` and `response_hash`.

## Known Risks

- **Cross-SDK hash divergence.** If the three SDKs redact responses differently, `response_hash` will not verify across implementations. This risk is elevated for responses (more variety, more nested structures) than for request parameters. Shared test vectors and a normative redaction algorithm are the mitigation.
- **Receipt size growth.** Adding one hash per receipt is negligible in bytes but normalizes the idea that receipts accumulate optional fields. The ADR should not open the door to storing the response itself; this must be explicit.
- **Migration surface area.** A `0.2.0` bump touches the spec, the JSON schema, three SDKs, the proxy verifier, examples, and any downstream tooling. A coordinated release is necessary; a staggered one will leave verifiers failing on valid receipts.
- **Option B requires caller discipline.** §3's verifier parameters only help callers who actually maintain external chain state. A caller who ignores them is no worse off than today but gains no protection. Operator guidance in the spec should explain when these parameters are expected to be supplied (e.g., any audit-trail use case with an external record should be passing `ExpectedFinalHash`).
- **Signature change concerns.** `response_hash` is part of the signed body. Any mismatch between what the issuer signed and what the verifier reconstructs will fail signature verification, which is correct. But it means that adding the field cannot be retrofitted to `0.1.0` receipts — the decision to hash must be made at receipt-creation time.

## Consequences

- Receipt schema version bumps from `0.1.0` to `0.2.0`. Verifiers must accept both; issuers may emit either, with clear guidance to prefer `0.2.0`.
- Spec §4.3 (outcome field reference) must be updated to describe `response_hash`, the ordering rule, and the verifier's handling of a missing field.
- Spec §7.3 (chain integrity verification) must gain a subsection stating explicitly that chain verification does not detect tail truncation, and document the `ExpectedLength` / `ExpectedFinalHash` verifier parameters as the supported mitigation.
- All three SDKs must implement response hashing on the issuer side and verification on the verifier side, plus the new optional verifier parameters, with shared test vectors in `sdk/shared-test-vectors/` (or equivalent) so cross-SDK interop is enforced in CI.
- Each SDK gains a test that pins `Valid: true` for a tail-truncated chain when no expected length/hash is supplied, and `Valid: false` when one is supplied and does not match. These tests lock current behaviour against silent future changes.
- `mcp-proxy verify` must validate `response_hash` when present and emit a clear diagnostic when the response body is not available for recomputation.
- New examples in `spec/examples/` demonstrating a `0.2.0` receipt with `response_hash`. Existing `0.1.0` examples are retained to document backwards compatibility.
- Migration notes in `spec/CHANGELOG.md` and a top-level upgrade section in the spec.
- Implementation should land as a single coordinated change across spec, schema, three SDKs, proxy, examples, and changelog, to avoid a window where the schema says one thing and the code says another.
- In-chain truncation detection (Options C and D) is explicitly deferred. If a real deployment surfaces a need for it, that work starts with a new ADR covering checkpoint semantics, verifier state, and any transparency-log coupling — not a bare schema field.

---

*Source: planning for #153 + #171, April 2026.*
