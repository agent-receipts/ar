# Disclosure-Envelope Test Vectors

Static expected-output fixtures for the `parameters_disclosure` asymmetric
envelope pinned by [ADR-0012](../../../docs/adr/0012-payload-disclosure-policy.md)
(see the *Amendment: envelope canonical shape and algorithm choice* section)
and described as a JSON Schema in
[`spec/schema/parameters-disclosure.schema.json`](../../schema/parameters-disclosure.schema.json).
These vectors fix the wire shape that the hub re-verifier (per ADR-0017) and
the three SDKs (Go, TS, Py) will consume. They are not yet wired into any
test suite.

## What this pins

The envelope is HPKE base-mode with the ciphersuite
`hpke-x25519-hkdf-sha256-aes-256-gcm` (RFC 9180 §7, IDs `0x0020 / 0x0001 / 0x0002`).
That choice is **accepted** — see the ADR-0012 amendment for the HPKE-vs-sealed-box
tradeoff and the rationale.

Each vector pins, simultaneously:

1. **Field set.** `v`, `alg`, `recipients[]`, `ct`. No `nonce` field
   (single-shot HPKE derives the AEAD nonce from the KEM output — surfacing it
   would be redundant and is treated as a schema violation in v1).
2. **Encoding.** Binary fields are unpadded base64url (RFC 4648 §5), matching
   the spec-wide convention from ADR-0009 / spec §4 `proofValue`. Standard
   base64 is not accepted.
3. **Canonicalisation.** Both the envelope JSON and the plaintext-before-encryption
   JSON use RFC 8785 JCS, identical to the rule already in force for the
   receipt envelope (ADR-0002).
4. **Recipient descriptor shape.** `kid` (DID URL or `sha256:` fingerprint) and
   `enc` (HPKE encapsulated key per RFC 9180 §4.1). The field is named `enc`
   to match the RFC; the original ADR-0012 sketch used `encap`, which is
   superseded by this PR.

## File format

`vectors.json` is a single JSON document with the following shape:

```
{
  "spec_version":   "parameters-disclosure envelope v1",
  "adr":            "docs/adr/0012-payload-disclosure-policy.md",
  "schema":         "spec/schema/parameters-disclosure.schema.json",
  "ciphersuite":    { ... },
  "encoding":       { ... },
  "test_recipients":[ { ... }, ... ],
  "vectors":        [ { ... }, ... ],
  "shape_invariants": { ... }
}
```

Each entry in `vectors[]` has:

| Field                       | Description                                                                                                          |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------|
| `name`                      | Stable identifier for cross-referencing in SDK test suites.                                                          |
| `description`               | One-line summary of what the vector exercises.                                                                       |
| `recipient`                 | Name of the entry in `test_recipients[]` to use as the recipient.                                                    |
| `plaintext_object`          | The parameters object before encryption, as a JSON value.                                                            |
| `plaintext_canonical_jcs`   | The RFC 8785 canonical JSON serialisation of `plaintext_object`. This is the AEAD plaintext.                         |
| `hpke_ephemeral.ikmE_hex`   | The deterministic input keying material for HPKE's `DeriveKeyPair` (RFC 9180 §7.1.3). Makes the envelope reproducible. |
| `envelope_canonical_jcs`    | The expected RFC 8785 canonical JSON of the envelope a conformant SDK MUST produce.                                  |
| `envelope_object`           | The same envelope as a structured JSON value, for readability.                                                       |
| `round_trip`                | The recipient private key and the plaintext a conformant decryptor MUST recover.                                     |

## Recipient test keys

Vectors use **well-known X25519 test keys only**:

- `forensic-test-recipient-1` uses the Alice key pair from [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1).
- `forensic-test-recipient-2` uses the Bob key pair from RFC 7748 §6.1.

Only the **public keys** are inlined in `vectors.json` (under `public_key_hex`).
The **private keys** are not inlined — even though the RFC publishes them as
plaintext, raw 32-byte hex literals that look like X25519 secret keys trip
secret-scanning tooling regardless of provenance, and inlining them encourages
cargo-cult reuse outside the test context. Reviewers running the decryption
round-trip fetch the private keys from RFC 7748 §6.1 directly.

These keys are famous, trivially recoverable from the RFC, and explicitly
unsuitable for production. **Do not regenerate them from fresh random keys;
the point of pinning these is that reviewers can reproduce the expected
outputs by hand from the RFC.**

## The deterministic-seed pattern for the HPKE ephemeral key

HPKE encryption is non-deterministic by default: the encryptor generates a
fresh ephemeral key pair (the `enc` output of `KEM.Encap`) for every
operation. That makes byte-identical cross-SDK test vectors impossible
without an extra knob.

RFC 9180 §7.1.3 specifies `DeriveKeyPair(ikm)`, a deterministic key-pair
derivation from input keying material. By pinning `ikmE_hex` per vector and
calling the HPKE library's deterministic-derivation path (e.g.
`HPKE_KEM_X25519_HKDF_SHA256.DeriveKeyPair(ikmE)` in the algorithmic spec; or
`SetupBaseS` with a supplied ephemeral key in implementations that expose it),
the encapsulated key `enc` and the AEAD ciphertext `ct` both become byte-stable
for a given plaintext and recipient public key.

Vector 1 uses the published `ikmE` from RFC 9180 §A.1.1 so reviewers can
sanity-check the `enc` against the RFC's own test vector. Vector 2 uses a
seed that is derived from a fixed, repo-local string and is documented inline
in `vectors.json`.

This pattern is for spec-side reproducibility only. **Production encryption
MUST use a fresh ephemeral key per operation** — the HPKE base mode's
security model assumes a fresh ephemeral key, and reusing an `ikmE` across
real encryptions would catastrophically break confidentiality.

## Reproducibility and the placeholder ciphertexts

The first revision of these vectors carries `"<enc-bytes-base64url-unpadded>"`
and `"<ciphertext-bytes-base64url-unpadded>"` placeholders for the concrete
output bytes. This is deliberate:

- The **canonical-JSON shape** (key order, alg string, kid form, encoding
  rule, presence/absence of `nonce`) is the load-bearing part this PR pins.
- The **concrete output bytes** are derivable from the recipient public key,
  the plaintext, the pinned ciphersuite, and `ikmE`. The first SDK to ship
  HPKE base-mode encryption with this ciphersuite will compute them; a
  follow-up PR fills them in, and from that point the three SDKs and the hub
  re-verifier must all produce byte-identical envelopes for these inputs.
- Holding placeholders rather than guessing is the conservative play. A
  wrong-looking `ct` that all three SDKs ended up matching (because they all
  loaded it from the same fixture) would silently lock in a bug; placeholders
  fail loudly until a real implementation lands.

Reviewers who want to spot-check today can compute HPKE base-mode against
RFC 9180 §A.1.1 by hand or with any conformant HPKE library and substitute
the values into the structure above. The schema constraints accept any
valid unpadded-base64url string of the right length for `enc` (43 chars,
the encoded size of a 32-byte X25519 public key) and any unpadded-base64url
string of `minLength: 22` for `ct`. The placeholder strings in the current
vectors (`<enc-bytes-base64url-unpadded>` / `<ciphertext-bytes-base64url-unpadded>`)
deliberately fail those checks — by design, since they should fail loudly if
copy-pasted into production. A vector's `computed_values_status` flips from
`"placeholder"` to `"computed"` when a follow-up PR fills in real values, and
from that point the vector is also expected to validate against the schema.

## What the vectors test

Each vector pins three things at once:

1. **Envelope-level JCS.** After encryption, the envelope JSON serialises to
   exactly the bytes in `envelope_canonical_jcs`. Top-level keys sort as
   `[alg, ct, recipients, v]`; recipient-entry keys sort as `[enc, kid]`.
2. **Plaintext-level JCS.** Before encryption, the parameters object is
   serialised under RFC 8785 to `plaintext_canonical_jcs`. Two SDKs that
   disagree about JCS produce different ciphertexts and a verifier will see
   mismatching `parameters_hash` values; that mismatch is the canonical
   cross-SDK bug class this fixture is meant to catch.
3. **Round-trip.** Decrypting `ct` with the recipient private key and the
   same ciphersuite recovers `plaintext_canonical_jcs` exactly. The
   round-trip property is what makes the envelope useful — without it, a
   forensic responder holding the key cannot read the disclosure.

`shape_invariants.rules[]` in `vectors.json` enumerates the schema-level
invariants every conformant envelope MUST satisfy, independent of the
concrete byte values. The cross-SDK harness will assert these directly.

## Status

These are spec-side reference fixtures. Each SDK will gain its own HPKE
encrypt/decrypt path and load these vectors in a follow-up track; the
cross-language test harness in `cross-sdk-tests/` will be extended to assert
SDK-produced envelopes byte-equal the `envelope_canonical_jcs` field here
under RFC 8785 canonicalisation. The HPKE-vs-sealed-box choice remains open
pending user sign-off on the ADR-0012 amendment — if the choice flips, this
directory's vectors are regenerated (the schema and the file layout do not
change; only `alg` and the cryptographic outputs do).
