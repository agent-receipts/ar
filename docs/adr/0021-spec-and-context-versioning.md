# ADR-0021: Spec and JSON-LD Context Versioning, with Permanent Per-Version URLs

## Status

Proposed

## Context

The Agent Receipts spec text promises permanent per-version URLs
("subsequent versions will be published at distinct, permanent URLs; this URL
is frozen at v0.2.1 and will not change"). The project does not currently
honor that promise. The JSON-LD `@context` URL embedded in every receipt
produced by the SDKs (`https://agentreceipts.ai/context/v1`) returns 404 —
every receipt currently in existence references a context document that does
not resolve. The W3C VC data model the receipt envelope is built on
(ADR-0003) requires `@context` URLs to resolve.

The living-spec file `spec/spec/agent-receipt-spec-v0.1.md` has frontmatter
claiming `Version: 0.1.0` but contains features released as recently as
v0.4.0. The frontmatter is stale; the file's actual content corresponds to
v0.4.0.

At this stage of the project — early days, v0.4.0 is current, nobody is
citing per-version spec URLs in the wild — the proportionate response is to
fix the live correctness issue and establish forward-only conventions, not
to reconstruct four historical spec versions from git history for canonical
republication.

## Decision

### D1. Forward-only per-version spec files, starting at v0.4.0

The current living-spec file is migrated to `spec/v0.4.0/spec.md`, with
frontmatter corrected to `Version: 0.4.0`. The legacy path
`spec/spec/agent-receipt-spec-v0.1.md` is deleted after migration.

From v0.4.0 onward, each released spec version is its own immutable file at
`spec/v<X.Y.Z>/spec.md`. Editorial corrections to a released version are not
made in place; they are made by releasing a new version with a CHANGELOG
entry noting the correction.

Earlier released versions (v0.1.0–v0.3.0) are not backfilled. They remain
accessible via git tags and CHANGELOG entries. No canonical URLs are
published for them. If a citation need arises later, the version can be
reconstructed and published at that point; until then, this is not work the
project should pay for.

### D2. Permanent per-version URLs, from v0.4.0 onward

Every released spec version from v0.4.0 onward is published at
`https://agentreceipts.ai/spec/v<X.Y.Z>/` and that URL is permanent. Once
published, the URL MUST NOT be repurposed, redirected to a different version,
or returned as 404 except during deploy windows.

`https://agentreceipts.ai/spec/latest/` is a mutable site-only alias
pointing at the current version. No `spec/latest/` directory exists in the
repo. Receipts and the conformance suite MUST NOT reference `/spec/latest/`;
only versioned URLs.

A `https://agentreceipts.ai/spec/` index page lists released versions
(initially just v0.4.0) and marks the current one. The index grows as new
versions land.

### D3. JSON-LD context is versioned independently, by JSON-LD term changes only

The JSON-LD context lives at `https://agentreceipts.ai/context/v<N>` where
`<N>` is an integer (`1`, `2`, `3`, …), not a semver string. This URL form
matches the form already referenced in every released spec version's
`@context` array.

The context version bumps when and only when JSON-LD term definitions
change in a way that would alter how a receipt validates. Adding a new
optional field whose JSON-LD term is already implied by existing definitions
is not a bump. Renaming a field, or adding a field that requires its own
term definition, is.

The spec version and the context version are independent. Multiple spec
versions may share one context version. The current state is: every shipped
receipt across v0.1.0–v0.4.0 references
`@context: https://agentreceipts.ai/context/v1`, and that URL 404s. v1 is
authored as part of this ADR's implementation, defining the terms needed
across receipts produced under those spec versions. The source lives at
`spec/context/v<N>/context.jsonld` in the repo.

If a future spec version introduces a JSON-LD term change, it references a
new context version (e.g. `v2`); the old context URL remains permanent.

### D4. Lightweight tag-driven publishing

Tagging `spec-v<X.Y.Z>` causes the site build to publish that version at
`https://agentreceipts.ai/spec/v<X.Y.Z>/`. Tagging `context-v<N>` publishes
`spec/context/v<N>/context.jsonld` at `https://agentreceipts.ai/context/v<N>`.

The implementation is a site-build step, not a separate CI gate. The
project does not yet need fail-build conformance machinery for a single
context document and a single canonical spec version. If later experience
shows drift between the published context and SDK output, a conformance
check can be added.

### D5. Deprecation policy

Released spec and context versions are kept reachable indefinitely. There
is no "old enough to remove" threshold. Defects are fixed by releasing a
new version with a CHANGELOG entry; the defective version remains reachable
as a historical artifact. The `/spec/` index marks defective versions, if
any, and points to the version that resolves the defect.

## Out of scope for this ADR

- Backfilling spec versions v0.1.0–v0.3.0 as canonical URLs. Explicitly
  deferred per D1.
- A live-network `@context` resolution check in the cross-SDK conformance
  suite. Explicitly deferred per D4.
- Updating downstream pages (Overview, schema, verification, Article 12
  one-pager) to reflect v0.4.0. Independent docs work; file when prioritized.
- An SDK release pipeline analogous to the spec pipeline. Different scope.

## Consequences

- Every receipt in existence references a `@context` URL that resolves to a
  valid JSON-LD document. SDK receipts pass strict JSON-LD validation. This
  is the primary outcome.
- From v0.4.0 onward, the spec text's permanent-URL promise becomes
  operational reality. Citations of `https://agentreceipts.ai/spec/v0.4.0/`
  and every later release will resolve.
- Citations of pre-v0.4.0 spec URLs (e.g. `/spec/v0.2.1/`) continue to 404.
  Acceptable given the project's current adoption stage; revisitable if
  external citation pressure appears.
- The living-spec file is gone. The next spec version is drafted as its
  own file under `spec/v<NEXT>/spec.md`.
- The repo gains a `spec/v<X.Y.Z>/` directory per release and a
  `spec/context/v<N>/` directory per context version. No `spec/latest/`
  directory; "latest" is a site-only alias.
- Spec and context versions evolve independently. A spec-only release ships
  with no context bump. A context bump (rare) is independent of whatever
  spec is current.

## Implementation issues spawned by this ADR

Filed as separate issues, blocked on the PR that merges this ADR. Each is
labeled `adr-followup`.

- Author JSON-LD context v1 covering terms across receipts produced under
  v0.1.0–v0.4.0 (D3).
- Migrate the living spec to `spec/v0.4.0/spec.md` and publish at
  `https://agentreceipts.ai/spec/v0.4.0/` (D1, D2, D4).
- Publish the `/spec/` index page listing v0.4.0+ (D2).

---

*Closes #596 when merged.*
