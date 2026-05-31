# schema_conformance

Gate #6 from ADR-0024: SDK output schema-conformance at release time.

After a release is published to PyPI / npm / the Go proxy, this gate emits a
representative signed receipt using the **published** SDK artifact and
validates it against the repo's published JSON Schema
(`spec/schema/agent-receipt.schema.json`). A release whose SDK emits output
that drifts from the schema turns red here, before the version is treated as
good.

## Layout

| File | Role |
|------|------|
| `check.py` | Installs the released version, emits one receipt via the SDK's public API, and validates it against the schema. |
| `test_check.py` | Unit tests for the schema-validation core and stdout parsing (no SDK install, no network). |

## Run locally

```sh
python3 scripts/schema_conformance/test_check.py          # unit tests (no network)
python3 scripts/schema_conformance/check.py --lang py --version 0.10.0
python3 scripts/schema_conformance/check.py --lang ts --version 0.10.0
python3 scripts/schema_conformance/check.py --lang go --version 0.12.0
```

`check.py` and `test_check.py` need the `jsonschema` library, which is already
a dev dependency of the Python SDK (`sdk/py/pyproject.toml`). The CI jobs
install it explicitly so the gate does not depend on the SDK's dev extras
being present.

## What this gate checks

The SDK being released emits a receipt that conforms to the published JSON
Schema. Validation uses Draft 2020-12 with format assertion enabled, matching
`AssertFormat` in the in-tree Go validator
(`cross-sdk-tests/spec_schema_test.go`), so a regression to a non-RFC3339
timestamp fails here too.

## Targeted spec version

There is a single repo-tracked schema file. It validates every protocol
`version` it lists in its `version` enum, and each receipt carries its own
`version`. The schema ships from the same commit as the SDK, so the schema
validated against is the one released alongside the SDK (ADR-0021
coordination); no separate version selection is required.

## Relationship to Gates #1 and #2

Gate #1 (`readme-snippets`) checks documented snippets compile/run against the
published artifact. Gate #2 (`release-verify`) checks the registry resolved
exactly the tagged version. Gate #6 adds the output-shape assertion: the
receipt the published SDK actually emits validates against the schema. All
three jobs depend only on `release` and run in parallel; each must pass for a
release to be considered green.
