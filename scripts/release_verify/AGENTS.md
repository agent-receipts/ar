# release_verify

Gate #2 from ADR-0024: release round-trip verification.

After a release is published to PyPI / npm / the Go proxy, this gate
verifies that the public registry resolves **exactly** the tagged version
and that the installation succeeds in a clean environment.

## Layout

| File | Role |
|------|------|
| `check.py` | Installs the released version from the registry and asserts the resolved version matches the release tag. |
| `test_check.py` | Unit tests for the version-parsing and comparison logic (no registry calls). |

## Run locally

```sh
python3 scripts/release_verify/test_check.py          # unit tests (no network)
python3 scripts/release_verify/check.py --lang py --version 0.10.0
python3 scripts/release_verify/check.py --lang ts --version 0.10.0
python3 scripts/release_verify/check.py --lang go --version 0.12.0
```

## What this gate checks

1. **Version identity** — the registry returns exactly the version we tagged,
   not a yank-substitute, nearest match, or stale cache entry.
2. **Installability** — the artifact is fetchable in a clean environment.

Snippet consistency (documented code compiles against the fetched artifact)
is covered by Gate #1 (`scripts/readme_snippets/check.py --source published`)
which runs alongside this gate in each `release-sdk-*.yml` workflow.

## Relationship to Gate #1

Gate #1 (`readme-snippets`) runs first and checks that the snippets compile
against the published artifact. Gate #2 runs in the same workflow and adds
the version-identity assertion: "the thing that just got installed is
actually version X, not some other version the registry decided to give us."

Both gates must pass for a release to be considered green.
