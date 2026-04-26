# Changelog

All notable changes to `@agnt-rcpt/sdk-ts` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.5.0; earlier releases are recorded only in git history.
A repo-wide effort to auto-generate changelogs from Conventional Commits is
tracked in [#253](https://github.com/agent-receipts/ar/issues/253).

## [0.5.0] - 2026-04-27

### Added

- `parameters_preview?: Record<string, string>` field on the `Action` interface.
  An operator-controlled, additive map of field name → stringified value that
  sits alongside the existing `parameters_hash`. The hash continues to cover
  the full parameter set; the preview exists for human/auditor display only.

  **Safety invariant.** Receipts are signed and durable — any value placed in
  `parameters_preview` is permanent and visible to anyone who can read the
  receipt. Callers MUST restrict keys to an explicit operator-managed allowlist
  and MUST NOT populate this field from raw tool arguments. The SDK does not
  auto-populate or validate this field; enforcement lives outside the SDK
  today (typically at the proxy/operator layer). Taxonomy-level allowlist
  support is tracked in
  [#258](https://github.com/agent-receipts/ar/issues/258).
  Treat it the same way you would treat a log line that ships to long-term
  storage: never include secrets, credentials, tokens, PII, or any field
  whose value you have not deliberately classified as safe to retain.
