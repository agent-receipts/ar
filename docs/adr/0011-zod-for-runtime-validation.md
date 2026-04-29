# ADR-0011: Zod for runtime schema validation

## Status

Accepted

## Context

`parseReceiptJson` in the TypeScript SDK deserialised stored receipts with a
bare `JSON.parse(json) as AgentReceipt` cast. The cast is compile-time only —
a corrupt or partially-written SQLite row returns as a ghost-typed `AgentReceipt`
with missing or wrong-typed fields, which then flows silently into chain
verification, signature verification, and queries.

For an audit-trail library this is a correctness gap, not a cosmetic one.
The Python SDK validates via Pydantic `model_validate`; the Go SDK relies on
`json.Unmarshal` against a typed struct. The TypeScript SDK had no equivalent.

Issue #170 asked for runtime validation at the store-load boundary. Three
options were evaluated:

1. **Hand-written validator** — covers the need but is maintenance-heavy: every
   field added to the spec requires a parallel update in the validator, and
   there is no type-level guarantee that the two stay in sync.

2. **ajv + JSON Schema** — the spec ships JSON schemas, so this would be
   authoritative. However, ajv is a significantly larger dependency, JSON Schema
   and TypeScript types have different evolution cadences, and keeping both in
   sync would require additional tooling.

3. **Zod** — schemas are written in TypeScript alongside the types, `z.infer`
   ensures structural alignment at compile time, and the library is the de-facto
   standard for runtime validation in the TypeScript ecosystem (>30M weekly
   downloads, actively maintained).

## Decision

Adopt Zod for runtime validation at the store-load boundary. A Zod schema
mirroring every interface in `src/receipt/types.ts` is defined in
`src/receipt/schema.ts` and called inside `parseReceiptJson` after
`JSON.parse`. Schema objects are not strict (no `.strict()`) so unknown extra
fields introduced by newer SDK versions do not break older stores. The existing
`AgentReceipt` interface is kept unchanged; the schema type is structurally
compatible but separate.

This is the SDK's first runtime dependency.

## Consequences

- Corrupt or schema-invalid rows in the store now surface a clear, field-pathed
  error at load time rather than propagating ghost-typed values downstream.
- Zod adds approximately 50 KB to the installed package (tree-shaking applies
  for bundled consumers).
- Setting a precedent for a runtime dependency: future additions must clear the
  same bar (well-maintained, widely adopted, supply-chain vetted).
- Validation in `createReceipt`, `signReceipt`, and `verifyReceipt` is
  explicitly deferred; the same schema can be reused at those sites if issue
  #170 scope is expanded later.
- If cross-SDK schema consistency becomes a priority (ajv + canonical JSON
  Schema), a future ADR may supersede this one.
