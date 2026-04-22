# ADR-0009: Canonicalisation Profile and VC Field Name Commitment

## Status

Accepted

## Context

ADR-0002 adopted RFC 8785 as the canonicalisation algorithm and flagged two
open questions in its *Known Risks* section:

1. **`issuanceDate` vs `validFrom`** — the JSON schema used `validFrom`
   (W3C VC 2.0) while all three SDKs serialised `issuanceDate` (W3C VC 1.x).
   Field names are part of the canonical bytes; the mismatch meant the schema
   rejected every SDK-produced receipt.
2. **Nullable / optional field handling** — three different strategies across
   the SDKs (Python `exclude_none=True`, Go `omitempty`, TypeScript
   caller-verbatim) with a per-field workaround for `previous_receipt_hash`.
   No rule existed in the spec for implementers to follow.

The v0.2.0 release (ADR-0008) shipped `response_hash` and `chain.terminal`
on top of these unresolved questions. Every v0.2.0 receipt in the wild was
signed under whichever SDK's ad-hoc behaviour applied at creation time. The
two decisions below close the gaps.

Bug fixes to individual SDK canonicalisers (UTF-16 sort, HTML escape,
`parameters_hash` via `json.Marshal`) are tracked in issues #82, #86, and
#118 and documented in the relevant PR descriptions; they are conformance
fixes to ADR-0002, not new decisions, and are not repeated here.

## Decision

### 1. Null and optional field rule

**Required-nullable fields** (present in the schema's `required` array with
type `oneOf: [T, null]` or `["T", "null"]`) **MUST be emitted** with their
value, including the explicit JSON `null` literal when the value is null.
The sole current required-nullable field is
`credentialSubject.chain.previous_receipt_hash`.

**Optional fields** (absent from `required`) **MUST NOT be emitted when null
or absent.** An SDK that receives `null` on an optional field MUST normalise
it to absent before canonicalising. The canonical form of an optional field
is either the non-null value or nothing; `"error":null` is not a valid
canonical representation.

This collapses the three existing SDK strategies into one. It is compatible
with Go's `omitempty` on optional fields and with Python's `exclude_none`
pass — the only change is that both must be applied consistently to *all*
optional fields, not patched per-field. TypeScript types must be tightened so
callers cannot place `null` on optional fields (e.g. `error?: string` not
`error?: string | null`); the SDK's canonicalise step must also normalise
null → absent at runtime as belt-and-braces.

The spec (§7.1.1) gains normative language stating this rule. The JSON schema
is tightened: optional fields that previously declared `"type": ["string",
"null"]` now declare `"type": "string"` — the only remaining nullable type in
the schema is `previous_receipt_hash`.

### 2. VC field name: `issuanceDate`, committed indefinitely

The JSON schema and spec update to `issuanceDate`. The VC 2.0 name `validFrom`
is removed and mentioned once, in a note, as a known deviation.

Rationale: all three SDKs have emitted `issuanceDate` since the first
release. Every receipt ever signed commits to JSON bytes containing the key
`"issuanceDate"` — migrating to `validFrom` would invalidate those
signatures. ADR-0003 already documents two other intentional VC 2.0
deviations (URDNA2015 → RFC 8785; simplified signing input); this is a
continuation of that position.

### 3. Schema version bump: `0.2.0` → `0.2.1`

The schema version bumps to `0.2.1` to mark the two spec-level changes above
(field-name fix, nullable-type tightening). The wire format is unchanged for
any receipt produced by a released SDK: every such receipt uses `issuanceDate`
and no SDK has ever emitted `"error":null` or equivalent. Verifiers MUST
accept `0.1.0`, `0.2.0`, and `0.2.1`.

## Security Considerations

### Signature preservation is a testable invariant

The null-rule fix and VC-field-name fix must be signature-preserving for all
existing receipts. This is not assumed — it must be verified. The
`cross-sdk-tests/canonicalization_vectors.json` file added alongside this ADR
includes a `receipt_signature_preservation_legacy_0_2_0` vector that runs the
post-sweep canonicaliser over the pre-existing v020 receipt fixtures and
asserts the canonical bytes are identical and all signatures still verify. If
any receipt's bytes change, the release must instead carry a version marker
and dual-verify logic.

### Null normalisation must not swallow required fields

Rule 1 normalises null → absent on *optional* fields only. An implementation
bug that also applies this to `previous_receipt_hash` would silently drop the
field from the canonical form, producing a different hash without a schema
error. The `receipt_required_null_preserved` vector in
`canonicalization_vectors.json` catches this regression.

## Consequences

- `spec/schema/agent-receipt.schema.json`: `validFrom` → `issuanceDate`,
  version enum gains `"0.2.1"`, optional fields lose `null` from their type.
- Spec §4.3 (Field Reference) and all examples: `validFrom` → `issuanceDate`.
- ADR-0002 *Known Risks* section: `issuanceDate` / `validFrom` risk marked
  resolved, linking here.
- ADR-0003 *Decision* section: removes the "must be aligned" note on
  `validFrom`; states `issuanceDate` is the committed name.
- All three SDKs: null-normalisation rule applied consistently (see bug-fix
  PRs for implementation details).
- `cross-sdk-tests/canonicalization_vectors.json` added; all SDKs run it in
  CI and assert byte-equality on every vector.

---

*Closes #83, #84, #85. Conformance fixes for #82, #86, #118 ship in the same
release under their own PR descriptions.*
