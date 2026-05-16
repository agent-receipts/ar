## What

Brief description of the change.

## Why

Motivation — what problem does this solve?

## Checklist

- [ ] Tests pass for all changed components
- [ ] Linter passes (`go vet`, `ruff check`, `biome` as applicable)
- [ ] No real keys or secrets in the diff
- [ ] Cross-language tests pass (if receipt format, signing, or hashing changed)
- [ ] AGENTS.md updated (if project structure changed)
- [ ] Spec changes have been reviewed by a maintainer (if applicable)

## Security

- [ ] This PR touches crypto, auth, or secrets handling (if no, skip remaining items)
- [ ] Primitives and parameters have been reviewed
- [ ] All inputs are validated at trust boundaries
- [ ] Edge cases are tested (nil, empty, corrupted, concurrent)

> [!TIP]
> Request a Copilot review for automated checks against project conventions.
