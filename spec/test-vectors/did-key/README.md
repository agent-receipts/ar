# did:key Resolution Test Vectors

Static expected-output fixtures for `did:key` v0.7 resolution as pinned in
[ADR-0007](../../../docs/adr/0007-did-method-strategy.md). These vectors fix the wire
shape that the hub re-verifier and the three SDKs (Go, TS, Py) will consume; they
are not yet wired into any test suite.

## File format

`vectors.json` is a single JSON document with the following shape:

```
{
  "spec_version": "did:key v0.7",
  "adr":          "docs/adr/0007-did-method-strategy.md",
  "multicodec_prefix_hex": "ed01",
  "multibase_prefix":      "z (base58btc)",
  "vectors": [ { ... }, ... ]
}
```

Each entry in `vectors[]` has:

| Field            | Description                                                                           |
|------------------|---------------------------------------------------------------------------------------|
| `name`           | Stable identifier for cross-referencing in SDK test suites.                           |
| `source`         | Where the public key comes from (RFC, registry, etc.) so reviewers can reproduce it.  |
| `public_key_hex` | The 32 raw Ed25519 public-key bytes (RFC 8032 §5.1.5) encoded as lowercase hex.       |
| `did`            | The expected `did:key:z<...>` identifier produced by the resolution algorithm.        |
| `did_document`   | The full resolved DID Document a conformant resolver MUST produce for that key.       |

## What the vectors test

Each vector pins three things at once:

1. **Multicodec framing.** The byte sequence fed to base58btc is exactly `0xed 0x01`
   followed by the 32 raw public-key bytes — never PEM, SPKI, or any other wrapper.
2. **Multibase encoding choice.** `did:key` uses base58btc with the `z` prefix.
   This is *not* the same encoding ADR-0001 uses for receipt `proofValue` fingerprints
   (multibase base64url, `u` prefix). The two encodings must not be conflated; an
   `id`-shaped string starting with `u` is never a valid `did:key`, and a fingerprint
   starting with `z` is never a valid receipt `proofValue`.
3. **DID Document shape.** The resolved Document uses the W3C `Multikey` verification
   method (current recommendation), not the older `Ed25519VerificationKey2020`, with a
   single verification method referenced from both `authentication` and `assertionMethod`.

## Reproducibility

Vectors use deterministic public keys only — RFC 8032 §7.1 TEST 1 / TEST 2 and the
W3C `did:key` registry's Example 1. Do not regenerate them from fresh random
keys; reviewers must be able to recompute the expected outputs by hand from these
sources.

## Status

These are spec-side reference fixtures. Each SDK will gain its own resolver and
load these vectors in a follow-up track; the cross-language test harness in
`cross-sdk-tests/` will be extended to assert SDK-resolved DID Documents
byte-equal the `did_document` field here under RFC 8785 canonicalisation.
