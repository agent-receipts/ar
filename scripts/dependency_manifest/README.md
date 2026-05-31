# Dependency-manifest gate (Gate #10)

Gate #10 of the project verification contract (ADR-0024).

For the SDK being released, compares the dependencies actually resolved into the
artifact (the **installed** set) against the dependencies the SDK declares
directly (the **declared** set). Any installed dependency that is neither
declared nor allow-listed fails the gate. This catches "eager" transitive deps
that creep into a published artifact — a supply-chain risk for a cryptographic
protocol project (see AGENTS.md "Adding dependencies").

The comparison is manifest-vs-manifest: it reads committed files only and needs
no network and no package install.

## Run

```
python scripts/dependency_manifest/run.py <sdk>   # sdk = go | py | ts
```

Exits 0 when every installed runtime dependency is declared or allow-listed;
exits 1 (with a GitHub `::error::` annotation) on the first unexplained
dependency.

## What "installed" and "declared" mean per SDK

| SDK | Declared (documented) | Installed (resolved runtime) |
|-----|-----------------------|------------------------------|
| go  | direct `require`s in `go.mod` | direct + `// indirect` requires in `go.mod` |
| py  | `[project].dependencies` in `pyproject.toml` | runtime closure of those deps resolved from `uv.lock` (dev/optional extras excluded) |
| ts  | `dependencies` in `package.json` | runtime closure resolved from `pnpm-lock.yaml` snapshots (dev deps excluded); declared deps only if no lockfile |

Scope is the **runtime closure**. Dev/test/build tooling is intentionally out of
scope — it is not shipped to consumers, so an undeclared test tool is not a
supply-chain risk in the published artifact.

## Allowlist

`allowlist.json` records intentional dependencies that are installed but not
declared directly — legitimate transitive deps of the declared ones. Each entry
carries a `name` and a `justification`. An allow-listed name suppresses the
failure for that dependency. Anything installed-but-not-declared-and-not-
allowlisted fails the gate.

Format:

```json
{
  "go": [ { "name": "<module-path>", "justification": "<why it ships>" } ],
  "py": [ { "name": "<package>",     "justification": "<why it ships>" } ],
  "ts": [ { "name": "<package>",     "justification": "<why it ships>" } ]
}
```

The runner also emits a non-fatal `::warning::` for allow-listed names that are
no longer installed, so stale entries get pruned.

## Design choices (flagged for maintainer review)

These defaults keep the gate minimal and dependency-light. They are judgement
calls and may be revised:

- **Manifest-vs-manifest instead of full SBOM tooling.** No SBOM generator
  (Syft / CycloneDX / cyclonedx-py / cyclonedx-gomod) is pulled in — the gate
  parses the manifests and lockfiles the repo already commits. If a signed SBOM
  artifact later becomes a hard requirement, swap the resolver here for a pinned
  generator; the allowlist/comparison logic can stay.
- **Scope = runtime closure only.** Dev/test/build deps are excluded.
- **"Declared" = direct manifest declarations, not README prose.** The SDK
  READMEs describe dependencies in prose ("minimal runtime dependencies — zod
  …") but do not enumerate them machine-readably, so the manifest's own direct
  declarations are the documented set. If a structured per-README dependency
  list becomes the source of truth, point the parser there.
- **TS transitive resolution parses `pnpm-lock.yaml` directly** (no YAML
  dependency, no `pnpm install`). It walks `snapshots:` `dependencies:` /
  `optionalDependencies:` blocks from the runtime roots; dev-only packages keyed
  under the importer's `devDependencies:` are never reached.
