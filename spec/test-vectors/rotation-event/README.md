# Rotation event test vector

A worked example of a `credentialSubject.keyRotation` receipt, pinning the
canonical wire form proposed in the
[ADR-0015 amendment](../../../docs/adr/0015-key-rotation-byok-anchoring.md#amendment-rotation-event-envelope-placement-credentialsubjectkeyrotation).

The vector is intended for human review of the proposal — runnable cross-SDK
verification (alongside `cross-sdk-tests/v020_vectors.json` and friends) is a
follow-up that depends on the placement decision being accepted.

## What this vector demonstrates

- The `credentialSubject.keyRotation` field carrying the seven rotation-event
  fields named in [ADR-0015 §"Rotation event schema"](../../../docs/adr/0015-key-rotation-byok-anchoring.md#rotation-event-schema)
  (`event_type`, `new_public_key`, `old_key_fingerprint`, `new_key_fingerprint`,
  `old_algorithm`, `new_algorithm`, `signed_with`).
- A receipt body that round-trips through
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonicalisation
  (per [ADR-0009](../../../docs/adr/0009-canonicalization-and-schema-consistency.md))
  and is signed end-to-end with the *outgoing* key (`signed_with: "old"`).
- All other receipt fields exactly as a `0.2.1` receipt already requires —
  this vector adds `keyRotation` and nothing else.

## Test keys

Both keys are well-known [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
test vectors. They MUST NOT be used in production.

| Role | RFC 8032 vector | Public key (hex) |
|---|---|---|
| Outgoing (signs the rotation) | TEST 2 | `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` |
| Incoming | TEST 3 | `fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025` |

Outgoing secret seed (TEST 2):
`4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`.

## Derived values (recomputable from the keys above)

- `old_key_fingerprint`: `sha256:39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f`
- `new_key_fingerprint`: `sha256:dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e`
- `new_public_key` (multibase-`u` base64url of the 32 raw bytes, per ADR-0001):
  `u_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU`
- RFC 8785 canonical bytes of the receipt body (`proof` removed) hash to
  `sha256:17e1384171b42a9ec356daebe773238cd8d8d0f476ff53f3313e7bf17bf5b517`.
  This is the value the next receipt in the chain would carry as
  `previous_receipt_hash`.
- Ed25519 signature over those canonical bytes, signed by the outgoing key,
  base64url-encoded with the multibase `u` prefix:
  `uTGn6rMIL7sGgZ22QRf9zOvNuqQINhvVgD-KQsnjHNS-E_FvouEeHPEv2tcDxmta1gauGp2-OXU3UGyFVr19tBA`

## Out of scope

- No JSON Schema integration. The current `spec/schema/agent-receipt.schema.json`
  does **not** set `additionalProperties: false` on `credentialSubject`, so the
  vector is already structurally accepted; tightening the schema with a
  `keyRotation` `$ref` is a follow-up gated on the placement decision being
  accepted.
- No cross-SDK runner. The proposed `keyRotation` namespace is not yet
  implemented in any SDK; once it is, this vector can be promoted into the
  `cross-sdk-tests/` harness.
- No rotation event anchored to an external sink. ADR-0015 specifies that
  rotation events MUST be anchored before the local chain commits — this
  fixture is a *wire-format* vector and is silent on the anchor write contract.
