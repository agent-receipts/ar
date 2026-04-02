# Governance

## Project stage

The Agent Receipt Protocol is in **draft** stage. The spec is under active development and subject to breaking changes.

## Decision-making

During the draft stage, decisions are made by the project maintainers. As the spec matures and gains adoption, governance will evolve toward a more formal process (e.g., an editorial board or working group).

## Roles

### Maintainers

Maintainers have write access to the spec repo and are responsible for reviewing and merging contributions.

Current maintainers:

- Otto Jongerius ([@ojongerius](https://github.com/ojongerius))

### Contributors

Anyone who opens an issue or pull request is a contributor. Contributors are expected to follow the [contributing guidelines](CONTRIBUTING.md).

## Spec lifecycle

| Stage | Description |
|---|---|
| **Draft** | Active development. Breaking changes expected. Current stage. |
| **Candidate** | Feature-complete. Seeking implementer feedback. Breaking changes discouraged. |
| **Stable** | Production-ready. Breaking changes require a new major version. |

Progression from one stage to the next requires:

1. At least one reference implementation that passes the JSON Schema and chain verification tests.
2. Review by at least two independent implementers or domain experts.
3. Resolution of all open questions marked as blocking for that stage.

## Versioning

The spec follows [Semantic Versioning](https://semver.org/):

- **Major** (1.0, 2.0): breaking changes to the receipt format, required fields, or verification algorithm.
- **Minor** (0.2, 0.3): new optional fields, new taxonomy domains, new verification features.
- **Patch** (0.1.1): clarifications, typo fixes, example corrections.

The `version` field in receipts is a full semantic version (`major.minor.patch`), for example `0.1.0`. Patch-level changes are reserved for clarifications and do not affect receipt compatibility.

During the draft stage (0.x), minor versions may include breaking changes.
