# ADR-0021: Spec and JSON-LD Context Versioning, with Permanent Per-Version URLs

## Status

Proposed

## Context

The Agent Receipts spec text promises permanent per-version URLs ("subsequent
versions will be published at distinct, permanent URLs; this URL is frozen at
v0.2.1 and will not change"). The project does not currently honor that
promise. Five released spec versions (v0.1.0, v0.2.0, v0.2.1, v0.3.0, v0.4.0)
have no canonical URL on the live site. The JSON-LD `@context` URL embedded
in every receipt produced by the SDKs (`https://agentreceipts.ai/context/v1`)
returns 404, meaning every receipt currently in existence references a context
document that does not resolve.

A site audit on 2026-05-24 found:

- `https://agentreceipts.ai/spec/v0.2.1/` returns 404 (SITE-P7).
- `https://agentreceipts.ai/context/v1` returns 404.
- Current spec source is a single living file
  (`spec/spec/agent-receipt-spec-v0.1.md`), not version-per-file.
- That file's frontmatter claims `Version: 0.1.0` but its content includes
  features released as recently as v0.4.0 (`idempotency_key`,
  `chain.terminal` / `chain.status`, `outcome.response_hash`, `unknown`
  action-type fallback). The frontmatter is stale and the file's actual
  content corresponds to v0.4.0.
- No JSON-LD context document exists in the repo.
- Five spec versions have shipped (latest: v0.4.0, 2026-05-23) with no
  versioned URLs published for any of them.

The W3C Verifiable Credentials Data Model the receipt envelope is built on
(ADR-0003) requires `@context` URLs to resolve to valid JSON-LD context
documents. A receipt validator that strictly processes JSON-LD against an
Agent Receipt today fails on context resolution. This is a correctness issue,
not just a documentation gap. The cross-SDK conformance suite has apparently
been getting away with not strictly validating JSON-LD, since every receipt
it produces references an unresolvable context URL.

This ADR records the decision to operate a spec release pipeline that makes
the spec text's promise true, and specifies the versioning model for both
the spec and the JSON-LD context.

## Decisions

### D1. Spec is versioned per file, in the repo, under `spec/`

The source of truth for spec version `vX.Y.Z` is `spec/v<X.Y.Z>/spec.md` in
the repo. Each version is immutable once tagged. Editorial corrections to a
released version are not made in place; they are made by releasing a new
version with a CHANGELOG entry noting the correction.

The current single-file living spec (`spec/spec/agent-receipt-spec-v0.1.md`)
is migrated: its current contents — which actually correspond to v0.4.0, not
the v0.1.0 its frontmatter claims — become `spec/v0.4.0/spec.md`, with
frontmatter corrected to `Version: 0.4.0`. The legacy path is deleted after
migration.

Earlier released versions (v0.1.0, v0.2.0, v0.2.1, v0.3.0) are reconstructed
from git history and placed at `spec/v<X.Y.Z>/spec.md`. Where git history
does not cleanly identify a "this commit is the v0.X release" state, the
closest commit to the release date is used and a note recorded in the
backfill issue.

### D2. Permanent per-version URLs

Every released spec version is published at
`https://agentreceipts.ai/spec/v<X.Y.Z>/` and that URL is permanent. Once
published, the URL MUST NOT be repurposed, redirected to a different version,
or returned as 404 except during deploy windows.

`https://agentreceipts.ai/spec/latest/` is a mutable alias pointing at the
current version. Receipts and the conformance suite MUST NOT reference
`/spec/latest/`; only versioned URLs.

A `https://agentreceipts.ai/spec/` index page lists all released versions,
marks the current one, and links to each.

### D3. JSON-LD context is versioned independently, by JSON-LD term changes only

The JSON-LD context lives at `https://agentreceipts.ai/context/v<N>` where
`<N>` is an integer (`1`, `2`, `3`, …), not a semver string. This URL form
(no trailing slash, no `v<N>/` directory) matches the form already referenced
in every released spec version's `@context` array.

The context version bumps when and only when JSON-LD term definitions change
in a way that would alter how a receipt validates. Renaming a field is a
context bump. Adding a new optional field whose JSON-LD term is already
implied by existing definitions is not. Adding a new field that requires its
own term definition is.

The spec version and the context version are independent. Multiple spec
versions may share one context version. The current state is: all five
released spec versions reference `@context: https://agentreceipts.ai/context/v1`.
This ADR is responsible for authoring v1 and ensuring it correctly defines
the terms used across all five spec versions, including any field renames
introduced in v0.3.0 and v0.4.0.

If a future spec version introduces a JSON-LD term change, that spec
version's `@context` array changes to reference the new context version
(e.g. `v2`). The old context URL remains permanent.

The context document is authored as part of this ADR's implementation. The
source lives at `spec/context/v<N>/context.jsonld` in the repo.

### D4. Release pipeline

Spec releases are tag-driven. Tagging `spec-v<X.Y.Z>` triggers a workflow
that:

1. Verifies `spec/v<X.Y.Z>/spec.md` exists in the repo.
2. Renders the spec markdown to a site page at
   `site/src/content/docs/spec/v<X.Y.Z>.mdx`.
3. Updates `spec/latest/` alias to point at the new version.
4. Updates the `/spec/` index page to list the new version.
5. Validates that every `@context` URL referenced in the new spec resolves
   on the live site (fail-build if not).
6. Deploys.

Context releases are tag-driven similarly: tagging `context-v<N>` publishes
`spec/context/v<N>/context.jsonld` at `https://agentreceipts.ai/context/v<N>`.

The workflow specs live at `.github/workflows/spec-release.yml` and
`.github/workflows/context-release.yml`.

### D5. Retroactive tagging for existing versions

After D1's backfill, the existing five spec versions are tagged retroactively
(`spec-v0.1.0` through `spec-v0.4.0`) on the commit that landed the
backfilled file. This validates the pipeline on past data: if it can't
publish the five existing versions, it can't publish the next one.

Context v1 is tagged once the context document is authored and validated
against the conformance suite (D6).

### D6. Conformance validates `@context` resolution

The cross-SDK conformance suite is updated to assert that every receipt it
produces has `@context` URLs that resolve to valid JSON-LD on the live site,
not just URLs that look correct as strings. This closes the loop: the bug
this ADR exists to fix becomes a property the project tests.

If conformance fails for a context URL, the release pipeline (D4) fails the
build. The project cannot ship a spec version that references a context
document the live site cannot serve.

### D7. Deprecation policy for old versions

Released spec and context versions are kept reachable indefinitely. There is
no "old enough to remove" threshold; every citation must remain valid.

If a released version contains a defect (e.g. the multibase encoding
inconsistency in v0.2.1 §4.2), the defect is not patched in place. A new
version is released with the correction. The defective version remains
reachable as a historical artifact. The `/spec/` index marks defective
versions and points to the version that resolves the defect.

## Out of scope for this ADR

- Updating downstream pages (Overview, schema, verification, Article 12
  one-pager) to reflect v0.4.0. Tracked in follow-up issues; depends on this
  ADR landing.
- Authoring an SDK release pipeline analogous to the spec pipeline.
  Different scope, similar shape.
- The site content-drift CI gate from the site audit. Adjacent; tracked
  separately.

## Consequences

- The spec text's permanent-URL promise becomes operational reality rather
  than aspirational language. Citations of `https://agentreceipts.ai/spec/v0.2.1/`
  and every other released version will resolve.
- Every receipt in existence — past and future — references a `@context` URL
  that resolves to a valid JSON-LD document. Strict JSON-LD validators no
  longer reject Agent Receipts on context-resolution failure.
- The release pipeline (D4) makes it structurally hard to ship a spec
  version whose context URL does not resolve, since the build fails before
  deploy. This converts a class of correctness bug into a CI failure.
- The repo gains a `spec/v<X.Y.Z>/` directory per release and a
  `spec/context/v<N>/` directory per context version. The legacy living-file
  path is removed. Contributors editing the current draft do so against
  `spec/latest/` working copy conventions established by the backfill issue.
- Spec and context versions evolve independently. A spec-only release (e.g.
  a clarification that does not change JSON-LD terms) ships with no context
  bump. A context bump (rare, term-level changes only) is independent of
  whatever spec is current at the time.
- The cross-SDK conformance suite gains a live-network dependency on the
  deployed site for `@context` resolution checks. CI must tolerate transient
  network failures by retrying, not by skipping the check.
- Defective released versions remain published as historical artifacts.
  Auditors verifying receipts produced under a defective spec version can
  still resolve the exact spec text the receipt was signed against.

## Implementation issues spawned by this ADR

Filed as separate issues, blocked on the PR that merges this ADR. Each is
labeled `adr-followup`.

- Backfill spec versions v0.1.0 through v0.4.0 from git history (D1, D5).
- Author JSON-LD context v1 covering terms across all five spec versions (D3).
- Build `spec-release` and `context-release` GitHub Actions workflows (D4).
- Update conformance suite to validate `@context` URL resolution (D6).
- Publish `/spec/` index page (D2).
- Update Article 12 one-pager for v0.4.0 schema and publish at canonical URL
  (downstream).
- Update Overview, schema, verification pages to v0.4.0 (downstream).

---

*Closes #596 when merged.*
