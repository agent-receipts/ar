# byte_identity

Gate #7 from ADR-0024: cross-SDK byte-identity at release time.

After a release is published to PyPI / npm / the Go proxy, this gate runs the
shared canonicalisation vectors
(`cross-sdk-tests/canonicalization_vectors.json`) through the **published** SDK
artifact's public canonicalisation/hash API and asserts the output is
byte-identical to the committed expected bytes (and the committed SHA-256
hashes). A release whose canonicalisation drifts — and therefore diverges from
the other SDKs, which are pinned to the same vectors — turns red here, before
the version is treated as good.

## Layout

| File | Role |
|------|------|
| `check.py` | Installs the released version, runs the vectors through the SDK's public API, and compares the output to the committed vectors byte-for-byte. |
| `test_check.py` | Unit tests for the comparison core (`compare_actuals`, `SAME_AS_`/skip resolution, stdout parsing). No SDK install, no network. |

## Run locally

```sh
python3 scripts/byte_identity/test_check.py            # unit tests (no network)
python3 scripts/byte_identity/check.py --lang py --version 0.10.0
python3 scripts/byte_identity/check.py --lang ts --version 0.10.0
python3 scripts/byte_identity/check.py --lang go --version 0.9.0
```

`check.py` and `test_check.py` use only the Python standard library
(`hashlib`, `json`); there is no third-party dependency to install.

## What this gate checks

The SDK being released reproduces, byte-for-byte:

- every `canonicalization_vectors[].canonical` via the SDK's public
  `canonicalize` (the RFC 8785 property ADR-0002 commits to), and the pinned
  `expectedHash` SHA-256 where present; and
- every pinned `receipt_hash_vectors[].expectedHash` via the SDK's public
  receipt-hash path.

`SAME_AS_<name>` invariants are resolved against the referenced vector's hash;
`COMPUTE_AT_COMMIT_TIME` placeholders and `receiptsFrom`-only
signature-preservation vectors carry no byte to compare and are skipped —
matching the in-tree per-SDK suites.

The Go driver reproduces the receipt hash via the SDK's public `Canonicalize` +
`SHA256Hash` on a `map[string]any` (after the documented ADR-0009 Rule 2
null-strip), because the public `HashReceipt` takes a typed
`receipt.AgentReceipt` that — since the v0.3.0 envelope migration (ADR-0012) —
cannot round-trip the legacy flat-map shape some vectors pin. The canonicaliser
remains the unit under test, exactly as in `sdk/go`'s in-tree vectors test.

## Targeted vectors version

There is a single repo-tracked vectors file. It ships from the same commit as
the SDK, so the vectors compared against are those released alongside the SDK;
no separate version selection is required.

## Relationship to the in-tree vectors tests and the other gates

The per-SDK in-tree tests (`sdk/{go,ts,py}` canonicalisation-vectors tests)
check the same property at PR time against in-tree source — never
release-blocking. Gate #7 moves the assertion to a release-blocking position
against the artifact consumers actually install. It runs alongside Gate #1
(`readme-snippets`), Gate #2 (`release-verify`), and Gate #6
(`schema-conformance`); all four depend only on `release` and run in parallel,
and each must pass for a release to be considered green.
