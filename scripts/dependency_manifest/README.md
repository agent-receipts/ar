# dependency_manifest — Gate #10 (ADR-0024)

Verifies that the dependencies actually resolved into each SDK's published
artifact match what the SDK declares, failing a release on any undeclared,
non-allow-listed runtime dependency.

## Usage

```sh
# Validate a specific SDK's dependency manifest (run from the repo root)
python3 scripts/dependency_manifest/check.py --lang go
python3 scripts/dependency_manifest/check.py --lang py
python3 scripts/dependency_manifest/check.py --lang ts

# Run the unit tests (no network, no install)
python3 scripts/dependency_manifest/test_check.py
```

`check.py` exits non-zero (with a `::error::` annotation) when an installed
runtime dependency is neither declared in the SDK's manifest nor recorded in
`allowlist.json`. It emits a non-fatal `::warning::` for stale allowlist
entries (allow-listed but no longer installed).

## What it compares

Manifest-vs-manifest, using only the Python standard library — no network and
no package install:

| SDK | Declared | Installed (resolved runtime) |
|-----|----------|------------------------------|
| go  | direct `require`s in `go.mod` | direct + `// indirect` requires in `go.mod` |
| py  | `[project].dependencies` in `pyproject.toml` | runtime closure from `uv.lock` (dev/optional extras excluded) |
| ts  | `dependencies` in `package.json` | runtime closure from `pnpm-lock.yaml` snapshots (dev tree excluded) |

## Allowlist

`allowlist.json` is keyed by SDK; each entry is `{ "name", "justification" }`.
An allow-listed dependency suppresses the failure for that name, so adding a
runtime dependency requires an allowlist entry with a justification — the
release-time enforcement of the SDKs' "minimal runtime dependencies" claim.

## Relationship to the other gates

Mirrors the `schema_conformance` (Gate #6) and `byte_identity` (Gate #7)
helpers: a per-SDK release-blocking job in each `release-sdk-*.yml` that runs
`check.py` then `test_check.py`.
