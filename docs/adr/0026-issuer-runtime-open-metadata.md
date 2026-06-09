# ADR-0026: Open `issuer.runtime` Metadata Sub-Object

## Status

Accepted

## Context

Claude Code, and runtimes like it, attach increasing amounts of *runtime
metadata* to each action: which sub-agent issued it, what type that agent is,
and — as observability standards mature (W3C Trace Context, OpenTelemetry GenAI
conventions; see #762) — trace and span identifiers. This metadata belongs on
the receipt `issuer`: it describes *who/what produced the action*, alongside the
existing `name`, `model`, `operator`, and `session_id` fields.

The immediate trigger: Claude Code already sends `agent_id` (and `agent_type`)
in its PostToolUse hook payload for sub-agents, and the hook → emitter → daemon
pipeline already forwards `agent_id` for chain routing — but the daemon dropped
it from the signed receipt issuer, so sub-agent receipts were indistinguishable
from root-agent receipts in the store and dashboard. PR #761 was opened to close
that gap by adding `agent_id`/`agent_type` as top-level issuer fields.

Adding them top-level surfaced a structural problem. The `issuer` object in the
JSON Schema is `additionalProperties: false`, and the JSON-LD context
(`spec/context/v1`) is `@protected` with no `@vocab` fallback — every term must
be explicitly defined. Under that design:

- **Every** new top-level issuer field is a breaking change for a strict
  verifier holding a pinned copy of the released schema: an unknown key fails
  `additionalProperties: false`, independently of whether the signature verifies
  (schema validation and signature verification are separate gates).
- A field whose JSON-LD term is undefined in the context (as `agent_id` /
  `agent_type` would be under v1) is silently dropped on JSON-LD expansion, so a
  W3C VC processor never sees it (ADR-0003 commits us to VC-valid receipts).
- Per ADR-0021 D1, released spec versions are immutable; a field addition is a
  *new spec version*, not an in-place edit. Per ADR-0021 D3, a new term that
  requires its own JSON-LD definition is a *context version bump*.

So each top-level issuer field costs a spec version, and — when it needs a new
term — a context version. `session_id` was added; `agent_id`/`agent_type` are
being added; `traceparent`/`trace_id` are coming with #762. On the current
trajectory the issuer accretes runtime metadata one expensive version bump at a
time, forever.

This ADR records a one-time structural change that removes that recurring tax.

## Decision

### D1. Runtime metadata lives in an open `issuer.runtime` sub-object

A new optional object, `issuer.runtime`, holds runtime/observability metadata
the issuing runtime attaches to an action. Its initially-defined members are:

- `agent_id` — identifier of the sub-agent that issued the receipt. Absent for
  the root agent.
- `agent_type` — runtime-reported agent type label (e.g. `"general-purpose"`).
  Absent for the root agent.

The root agent omits `runtime` entirely (`omitempty` / `None` / absent).

The top-level `issuer` object is unchanged and stays closed: `id`, `type`,
`name`, `operator`, `model`, `session_id` remain `additionalProperties: false`.
`runtime` is the *only* extensible region.

### D2. `runtime` is open at the schema, JSON-LD, AND SDK-typed layers

This is the load-bearing decision — it is what makes future runtime fields free.

- **JSON Schema:** the `runtime` object lists its known members with types and
  descriptions, but does **not** set `additionalProperties: false`. Unknown keys
  inside `runtime` validate, rather than failing.
- **JSON-LD context:** the `runtime` term is typed `"@type": "@json"` — the same
  treatment `action.parameters_disclosure` already uses. Its contents are an
  opaque JSON literal; JSON-LD never expands the inner keys, so no inner key
  ever requires a term definition.
- **SDK typed layer:** all three SDKs *preserve* unknown `runtime` keys across a
  round-trip, so a key a newer SDK adds is not silently dropped by an older one
  (which would diverge the canonical hash). TS uses an index signature, Python
  uses `extra="allow"`, and Go gives `Runtime` an `Extra map[string]json.RawMessage`
  with custom (un)marshalling. This is deliberately *unlike* the rest of the
  receipt struct, whose unknown fields are dropped (see Go `HashRawReceipt`):
  `runtime` is the one region that stays open end-to-end.

Consequence: a future runtime field (e.g. `traceparent`) is added to the JSON
Schema's `runtime` members for documentation, and ships with **no spec-version
or context-version bump** required for JSON-LD/VC validity. The one-time cost of
introducing `runtime` (D3) buys forward-compatibility for all later runtime
metadata.

This does not weaken integrity. The signature covers the canonical bytes of the
whole receipt including `runtime` (RFC 8785, ADR-0002), so runtime values are
tamper-evident. Openness is a *schema-strictness* property, not an integrity
one, and it is scoped to the runtime sub-object only — identity-bearing
top-level fields keep their closed content model.

### D3. Ships as spec v0.5.0 and JSON-LD context v2

Per ADR-0021:

- **Spec v0.5.0** — a new immutable `spec/v0.5.0/spec.md` (D1 of ADR-0021), the
  `version` enum gains `"0.5.0"`, and `spec/CHANGELOG.md` gets a `[0.5.0]`
  entry. The released v0.4.0 schema is **not** edited in place.
- **Context v2** — `runtime` is a new JSON-LD term, which ADR-0021 D3 makes a
  context bump. `spec/context/v2/context.jsonld` is authored (v1 plus the
  `runtime` `@json` term). Receipts at v0.5.0 reference
  `https://agentreceipts.ai/context/v2` in their `@context` array; v1 remains
  permanent for earlier receipts.

Spec and context versions remain independent (ADR-0021 D3); this release happens
to bump both because the structural change requires it.

### D4. Migration and compatibility

- v0.4.0 and earlier receipts are unchanged and remain valid. No issuer carries
  `runtime` below v0.5.0.
- The `agent_id`/`agent_type` top-level fields proposed in PR #761 are **not**
  shipped; they move into `runtime`. #761 is reworked to this shape (it is
  unmerged, so nothing released is broken).
- The daemon maps its existing emitter-frame `agent_id`/`agent_type` fields into
  `issuer.runtime` when building a v0.5.0 receipt. Emitter-frame and hook wire
  formats keep their flat `agent_id`/`agent_type` fields — only the *receipt*
  issuer structure nests them.
- New receipts SHOULD emit `"version": "0.5.0"`; verifiers MUST accept `0.5.0`.

### D5. What belongs in `runtime` vs. top-level issuer

To keep D2's openness from becoming a dumping ground:

- **Top-level issuer (closed, strict):** stable, identity-bearing facts about the
  issuing party — `id`, `operator`, `model`, `session_id`. New fields here are
  deliberate, versioned, term-defined additions.
- **`issuer.runtime` (open):** ephemeral, runtime-attested, observability-
  oriented metadata that is expected to track external standards (agent/span
  identifiers, trace context). Fields here are documentation in the schema, not
  gates.

When in doubt, a field that an auditor verifies *identity* with is top-level; a
field that a dashboard *correlates or visualizes* with is runtime.

### D6. Gates (per ADR-0024)

The new structure ships with its enforcement in the same release:

- The cross-SDK byte-identity / signature vectors gain v0.5.0 cases: a receipt
  carrying a populated `issuer.runtime`, a root receipt that omits it, and an
  **extended** receipt whose `runtime` carries a key beyond the typed members
  (`trace_id`). All three SDKs must preserve the unknown key and reproduce the
  pinned hash — the gate for the D2 open-container invariant. Go's runner hashes
  the extended receipt *through the typed struct* (`HashReceipt`), so a dropped
  key fails the test.
- The schema-conformance suite validates v0.5.0 examples (with and without
  `runtime`) against the v0.5.0 schema, and a negative test asserts the
  version↔context `allOf` coupling **rejects** mismatched pairings (0.5.0+v1 or
  ≤0.4.0+v2).
- The daemon bounds the runtime fields it writes: `agent_id` keeps its existing
  length + character validation (it is interpolated into chain IDs);
  `agent_type` gets the same `maxIdentityFieldLen` cap the other proxy-supplied
  identity fields have. `runtime` is gated on `agent_id` alone (matching chain
  routing), so a root-chain receipt never carries it. Schema openness governs
  *consumers*; the daemon still validates what it *produces*.

## Consequences

### Easier

- Runtime/observability metadata — including the OTel/trace fields in #762 —
  lands without a protocol-version or context bump from here on.
- Sub-agent receipts are distinguishable in the store and dashboard via
  `issuer.runtime.agent_id`, and the issuer maps cleanly onto OTel GenAI
  conventions (`gen_ai.agent.id`, `gen_ai.agent.name`).
- The expensive parts of schema evolution (closed identity model, immutable
  released versions) are preserved where they matter and relaxed only in the one
  region designed to grow.

### More difficult / costs

- One-time, large change: spec v0.5.0 + context v2 + the signed `@context` array
  bump rippling through all three SDKs and the cross-SDK vectors.
- Two ways to express "this came from a sub-agent" now exist in the ecosystem
  for a while: the nested v0.5.0 form and the (never-released) flat PR-#761 form.
  Mitigated by reworking #761 before it merges.
- `runtime` openness means a buggy or hostile emitter can attach arbitrary keys
  inside `runtime` that pass schema validation. They are signed (tamper-evident)
  and bounded by the 1 MiB frame cap, but consumers MUST treat unknown `runtime`
  keys as untrusted metadata, not as identity.

## Out of scope for this ADR

- The OTel trace-export work that consumes `runtime` (#762). This ADR makes it
  cheap; it does not implement it.
- A general extension mechanism for non-issuer parts of the receipt
  (`credentialSubject`, etc.). If those accrete open metadata later, they can
  follow this pattern; this ADR does not pre-commit them.
- `parent_agent_id` / deeper agent nesting. Not expressible today (sub-agents
  cannot spawn sub-agents in the current Claude Code toolset); revisit if that
  changes.

## Spawned follow-up work (not in this ADR's diff)

- Implement v0.5.0 across spec, context v2, the three SDKs, the daemon, and the
  cross-SDK vectors (reworks #761).
- Publish `spec/v0.5.0/` and `spec/context/v2/` per ADR-0021 D2/D4 tagging.
- Consume `issuer.runtime` in the OTel exporter (#762).
