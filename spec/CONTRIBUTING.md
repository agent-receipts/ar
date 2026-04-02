# Contributing to the Agent Receipt Protocol

Thank you for your interest in contributing to the Agent Receipt Protocol specification.

## How to contribute

### Reporting issues

Open a [GitHub issue](https://github.com/agent-receipts/spec/issues) for:

- Ambiguities or contradictions in the spec
- Missing fields or action types needed for your use case
- Compatibility concerns with W3C VC, C2PA, or other standards
- Errors in the JSON Schema or examples

### Proposing changes

1. Open an issue describing the change and its motivation.
2. Fork the repo and create a branch from `main`.
3. Make your changes. For spec text, follow the conventions below.
4. Open a pull request referencing the issue.

### Spec conventions

- Use [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keywords (MUST, SHOULD, MAY) for normative requirements.
- Keep examples valid against the JSON Schema (`schema/agent-receipt.schema.json`).
- Use `sha256:` prefixed 64-character lowercase hex for all example hashes.
- Use `urn:receipt:<uuid-v4>` format for receipt IDs and `act_<uuid-v4>` for action IDs.

### Adding action types

New standard taxonomy entries (§5) should:

- Follow the existing `domain.resource.verb` naming pattern.
- Include a default risk level with justification.
- Be motivated by a real use case, not speculative.

Custom (non-standard) action types use reverse-domain prefixes as described in §5.8.

### JSON Schema changes

If you modify the spec's field reference (§4.3), update the JSON Schema to match. Validate your changes against the full and minimal receipt examples before submitting.

## Code of conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
