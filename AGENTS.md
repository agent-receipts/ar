# AGENTS.md

Protocol specification for Agent Receipts — cryptographically signed, hash-chained audit trails for AI agent actions. This is a spec repo, not a code project.

## Repo structure

- `spec/agent-receipt-spec-v0.1.md` — the protocol specification (normative)
- `spec/taxonomy/action-types.json` — canonical action type definitions (source of truth)
- `schema/agent-receipt.schema.json` — JSON Schema (Draft 2020-12) for receipt validation
- `schema/taxonomy.schema.json` — JSON Schema for the taxonomy file

## Spec conventions

- Use RFC 2119 keywords: MUST, SHOULD, MAY (and their negatives)
- Receipt IDs: `urn:receipt:<uuid-v4>`
- Action IDs: `act_<uuid-v4>`
- Hashes: `sha256:` + 64-char lowercase hex
- Canonical action types in `spec/taxonomy/action-types.json` follow the `domain.resource.verb` pattern (exactly three dot-separated segments)
- Custom action types use reverse-domain prefixes with a canonical suffix, e.g. `com.acme.crm.lead.create`
- Examples in the spec must validate against the JSON Schema

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [GOVERNANCE.md](GOVERNANCE.md) for project status and versioning.

## Validation

CI runs `ajv` to validate JSON files against their schemas. To run locally:

```sh
npm install -g ajv-cli ajv-formats
ajv validate -s schema/taxonomy.schema.json -d spec/taxonomy/action-types.json --spec=draft2020 -c ajv-formats
ajv compile -s schema/agent-receipt.schema.json --spec=draft2020 -c ajv-formats
```

## Related repos

- [agent-receipts/site](https://github.com/agent-receipts/site) — documentation site
- [agent-receipts/sdk-ts](https://github.com/agent-receipts/sdk-ts) — TypeScript SDK
- [agent-receipts/sdk-py](https://github.com/agent-receipts/sdk-py) — Python SDK
