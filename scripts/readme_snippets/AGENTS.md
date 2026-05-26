# readme_snippets

Release-blocking check that the SDK code snippets in the user-facing READMEs
actually compile / type-check against the SDK. Catches the recurring papercut
(#593, #594) where a quick-start snippet calls a non-existent API, imports a
wrong module path, or drifts behind a published rename.

## Layout

| File | Role |
|------|------|
| `extract.py` | Pure fence extraction + per-language assembly. Unit tested. |
| `check.py` | IO + subprocess driver: scaffolds a throwaway project and runs the compiler/type-checker. |
| `test_extract.py` | Unit tests for `extract.py`. |

## Run locally

```sh
python3 scripts/readme_snippets/test_extract.py          # unit tests
# TypeScript local mode needs the in-tree dist built first:
( cd sdk/ts && pnpm install && pnpm run build )
python3 scripts/readme_snippets/check.py --lang go --source local README.md sdk/go/README.md
python3 scripts/readme_snippets/check.py --lang ts --source local README.md sdk/ts/README.md
python3 scripts/readme_snippets/check.py --lang py --source local README.md sdk/py/README.md
```

`--source local` builds against the in-tree SDK (used on PRs). `--source
published [--version X.Y.Z]` builds against the released artifact (used by the
publish-* workflows at release time).

## Per-language tooling

- **Go** — every snippet compiles as a non-main `package snippet` via `go build`
  (so a block with no `func main` still builds; unused funcs are allowed, unused
  imports/locals are not). Bare statement snippets are wrapped automatically.
- **TypeScript** — `tsc --noEmit --strict` against the installed package.
- **Python** — `mypy` against the installed package (`agent-receipts` ships
  `py.typed`). Type-check only; snippets are never executed.

## Authoring snippets

Every fenced `go` / `typescript` / `python` block that imports the SDK is
checked **by default** — that default is what catches drift on a newly added
snippet without anyone remembering to annotate it. Two invisible HTML-comment
directives override this when a block isn't standalone:

```md
<!-- snippet-check: continues -->   <!-- concatenate onto the previous checked block -->
<!-- snippet-check: skip -->        <!-- exclude (intentionally partial pseudo-code) -->
```

Place the directive on its own line immediately above the opening fence.

## Adding a README to the gate

1. Add its path to the `check.py` invocations in
   `.github/workflows/readme-snippets.yml` (and the relevant publish-* workflow
   for the release gate).
2. Run the local commands above and resolve any failures — prefer fixing the
   snippet over adding a `skip`.
