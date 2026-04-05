# ADR-0002: RFC 8785 for JSON Canonicalization

## Status

Accepted

## Context

The Agent Receipts protocol requires signing JSON receipts with Ed25519 (ADR-0001) and linking them into hash chains via SHA-256. Both operations take bytes as input, but JSON has no unique byte representation: key ordering, whitespace, and number formatting are all unspecified by RFC 8259. Two semantically identical receipts can produce different byte sequences, different hashes, and different signatures. Without a canonical form, a receipt signed by one SDK cannot be reliably verified by another, and chain integrity checks fail whenever serialization differs.

This is not a theoretical concern. The project ships three independent SDK implementations (Go, Python, TypeScript), each with its own JSON serializer. The canonical form must be specified precisely enough that all three produce byte-identical output for any valid receipt.

We evaluated the following alternatives:

- **JCS (RFC 8785 — JSON Canonicalization Scheme):** A lightweight canonicalization algorithm that sorts object keys lexicographically by UTF-16 code units and mandates ES6 `Number.toString()` semantics for number serialization. Works on plain JSON with no schema or context requirements.
- **JSON-LD canonicalization (RDF Dataset Canonicalization, W3C):** The default canonicalization method used by the W3C Verifiable Credentials Data Integrity specification. Requires `@context` resolution over the network, RDF graph normalization (URDNA2015), and JSON-LD processing. Significantly more complex to implement and test.
- **Custom canonical form:** Define our own serialization rules (e.g., sorted keys, no whitespace). No ecosystem support, high maintenance burden, and every edge case must be discovered and specified from scratch.
- **Binary formats (Protocol Buffers, CBOR):** Eliminate the canonicalization problem entirely by using a format with a single canonical encoding. However, this sacrifices JSON readability, makes debugging harder, and creates a format mismatch with the W3C VC ecosystem which is JSON-based.

Related: #40, #20 (parent issue).

## Decision

Use RFC 8785 (JSON Canonicalization Scheme) as the canonical serialization for all receipt hashing and signing operations.

The canonicalization procedure is: remove the `proof` field from the receipt, then serialize the remaining fields using RFC 8785. The resulting UTF-8 byte string is the input to both Ed25519 signing and SHA-256 hashing for chain linkage.

Key reasons:

- **Simple, well-specified algorithm** — the entire spec reduces to two rules: sort object keys lexicographically by UTF-16 code units, and serialize numbers using ECMAScript `Number.toString()` semantics. Minimal ambiguity means minimal implementation divergence.
- **Works on plain JSON** — no `@context` resolution, no RDF graph normalization, no network requests during canonicalization. A receipt can be canonicalized using only the receipt itself.
- **Good library support across target languages** — the algorithm is straightforward enough that all three SDKs (Go, Python, TypeScript) produce RFC 8785 output without external dependencies, keeping the dependency tree small and auditable. The TypeScript SDK relies on JavaScript's native UTF-16 string comparison and ES6 number serialization, which inherently conform to RFC 8785. Go and Python re-implement the ES6 `Number.toString()` algorithm and (in Python's case) UTF-16 code unit comparison explicitly.
- **Small spec surface area** — RFC 8785 is a short RFC. Less specification means less room for implementers to disagree on edge cases, which directly reduces cross-language divergence risk.
- **Proven in adjacent ecosystems** — RFC 8785 is used in JWS (JSON Web Signature) and JWK (JSON Web Key) contexts, and is referenced by the W3C VC Data Integrity specification as an alternative to JSON-LD canonicalization.
- **Alignment with W3C VC Data Integrity** — the spec notes (§7.1) that the canonicalization step is aligned with RFC 8785 usage in the W3C VC Data Integrity specification, though the overall signing procedure is intentionally simplified.

## Security Considerations

### Cross-implementation divergence

The security of every receipt signature depends on all SDK implementations producing byte-identical canonical output for the same input. If two implementations canonicalize a receipt differently, signatures created by one will not verify under the other. This is a real attack surface: an attacker who can construct a receipt that canonicalizes differently across SDKs could present a receipt that appears valid to one verifier but invalid to another, or produce two different hashes for the same logical receipt.

This risk is the same canonicalization dependency identified in ADR-0001's *Canonicalization dependency* section. Mitigation requires:

1. Shared cross-language test vectors (`sdk/py/tests/fixtures/ts_vectors.json`) that all SDKs must pass.
2. Test coverage for edge cases: Unicode strings, negative zero, deeply nested objects, empty objects and arrays, and keys that sort differently under UTF-8 vs UTF-16 ordering.
3. Fuzz testing of canonicalization implementations beyond the fixed test vectors.

### Proof field exclusion

The `proof` field MUST be removed from the receipt before canonicalization. The canonical bytes are the input to both signing (which produces `proof.proofValue`) and chain hashing (which produces the next receipt's `previous_receipt_hash`). If the `proof` field were included, signing would be circular — the signature would need to cover itself. All SDK implementations strip `proof` before canonicalization: TypeScript uses destructuring (`const { proof: _, ...unsigned }`), Python removes it with `dict.pop()` after Pydantic model serialization, and Go uses a separate `UnsignedAgentReceipt` type that omits the field entirely.

Any implementation that fails to exclude `proof` before canonicalization will produce signatures and hashes that are incompatible with all other implementations. This invariant must be enforced by cross-language test vectors.

### Unicode edge cases

RFC 8785 specifies that object keys are sorted by UTF-16 code unit order, not by Unicode code point order. For characters in the Basic Multilingual Plane (U+0000 to U+FFFF), these orderings are identical. They diverge for supplementary characters (emoji, CJK Extension B, etc.) which are represented as surrogate pairs in UTF-16. Implementations in languages that use UTF-8 natively (Go, Python) must correctly implement UTF-16 code unit comparison for key sorting. Python does this via `_utf16_sort_key()` which encodes keys as UTF-16-LE for comparison. The Go SDK currently uses `sort.Strings()` which sorts by UTF-8 byte order — this is correct for BMP characters but incorrect for supplementary characters (#82). The current SDKs include Unicode string test cases, but supplementary-character key ordering should be explicitly covered.

### Number serialization edge cases

RFC 8785 mandates ES6 `Number.toString()` semantics for number serialization, which requires the shortest decimal representation that round-trips to the same IEEE 754 double. Edge cases include: negative zero (must serialize as `"0"`), very large/small numbers requiring exponential notation, and numbers at the boundary of integer precision. Non-finite values (Infinity, NaN) are not valid JSON and all SDKs correctly reject them. Go and Python must re-implement the ES6 algorithm since their native number formatting does not match; divergence here is a realistic bug class.

### Nullable field handling across SDKs

The Python SDK uses `model_dump(exclude_none=True)` in all canonicalization paths, which silently drops fields with `None` values from the canonical representation. This requires special re-insertion logic for semantically meaningful null values — currently `previous_receipt_hash` is explicitly re-added as `null` for the first receipt in a chain. Go uses `omitempty` JSON tags and TypeScript includes all fields. Any new nullable field added to the receipt schema must be audited across all three SDKs to ensure they agree on whether `null` is included in or excluded from the canonical form. Disagreement on null-field inclusion is a concrete instance of the cross-implementation divergence risk described above.

### Test vector coverage requirements

Cross-language test vectors are the primary defense against canonicalization divergence. The current vectors (`sdk/py/tests/fixtures/ts_vectors.json`) cover simple object ordering, a full receipt structure, and hash/signature round-trips. This coverage should be expanded to include:

- Objects with keys that sort differently under UTF-8 vs UTF-16 ordering.
- Numbers at IEEE 754 precision boundaries.
- Strings with characters requiring JSON escaping (control characters, backslash, quotes).
- Deeply nested structures.
- The `parameters_hash` field, which itself contains an RFC 8785 canonical JSON hash.

## Known Risks

- **Not the W3C VC Data Integrity default.** The W3C VC Data Integrity specification uses JSON-LD canonicalization (RDF Dataset Canonicalization) as its primary method. By choosing RFC 8785, Agent Receipts diverge from tooling that assumes JSON-LD processing. This is acceptable because: (1) the protocol does not require JSON-LD features like `@context` resolution or RDF graph operations, (2) RFC 8785 is explicitly acknowledged by the W3C VC ecosystem as a valid alternative, and (3) the simplicity of RFC 8785 directly reduces cross-implementation divergence risk, which is the primary threat to a multi-SDK protocol.
- **Fewer battle-tested implementations in the VC ecosystem.** JSON-LD canonicalization has more deployment history in the Verifiable Credentials ecosystem specifically. RFC 8785 is newer and has fewer large-scale deployments to learn from. This is mitigated by the algorithm's simplicity and the project's investment in cross-language test vectors.
- **Custom implementations in Go and Python.** Rather than using external RFC 8785 libraries, all three SDKs implement the algorithm directly. This gives full control and avoids dependency risk, but means each implementation must be independently verified for correctness. Any future SDK must also implement (or adopt a library for) RFC 8785 and pass the shared test vectors.
- **`issuanceDate` vs `validFrom` field naming.** The spec (VC Data Model 2.0) uses `validFrom` while all three SDKs currently use `issuanceDate` (VC Data Model 1.x naming). Since field names affect canonical byte output, any mismatch between implementations would break cross-SDK verification. This naming must be aligned — either the spec or the SDKs should be updated to match. See the Go SDK's `types.go` comment documenting this divergence.

## Consequences

- All SDKs (Go, Python, TypeScript) must implement RFC 8785 compliant canonicalization and must pass shared cross-language test vectors.
- The `proof` field exclusion before canonicalization is a protocol-level invariant that must be enforced in every SDK and verified by cross-language tests.
- Receipt hashing (`previous_receipt_hash`) and signing both use the same canonical bytes, simplifying the implementation and reducing the surface area for bugs.
- The protocol diverges from W3C VC Data Integrity's JSON-LD canonicalization approach. This is documented and intentional — the simplicity trade-off is the right one for a protocol that must produce byte-identical output across three independent implementations.
- Adding a new SDK language requires implementing RFC 8785 (or adopting a compliant library) and passing the existing cross-language test vectors before the SDK can interoperate.
- Cross-language canonicalization test vectors are a hard requirement, not optional. Expanding test coverage for Unicode and number edge cases is an ongoing obligation.
