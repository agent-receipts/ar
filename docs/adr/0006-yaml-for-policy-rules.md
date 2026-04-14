# ADR-0006: YAML for Policy Rule Configuration (mcp-proxy)

## Status

Accepted

## Context

The mcp-proxy policy engine needs a configuration format for defining rules that classify, score, and gate MCP tool calls. Rules match on tool name patterns, server name patterns, operation types, and risk score thresholds, and map to one of four actions: pass, flag, pause, or block.

The target audience for writing and maintaining policy rules is platform engineers and security operators — not necessarily the developers who built the proxy. The format must be readable and editable without specialized tooling.

We evaluated the following alternatives:

- **JSON:** Ubiquitous and well-supported, but lacks comments, requires strict quoting and trailing-comma discipline, and is noticeably noisier for the flat list-of-rules structure policy files use. JSON is better suited for machine-to-machine interchange than for files humans maintain by hand.
- **OPA/Rego:** Purpose-built for policy-as-code and extremely powerful for complex cross-resource decisions. However, Rego introduces a dedicated language with its own learning curve, requires embedding or sidecarring the OPA runtime, and is significant overkill for the current rule model (glob matching + severity ordering). The complexity is not justified when the policy surface is a flat list of pattern-matching rules.
- **Programmatic Go API (no config file):** Embedding rules in Go code removes the serialization layer entirely, but couples policy changes to code deployments. Operators cannot adjust rules without recompiling, and non-Go contributors cannot participate in policy authoring. This conflicts with the goal of operator-editable configuration.
- **CUE / Jsonnet / HCL:** Each adds a templating or constraint layer. Useful when config is large, deeply nested, or needs cross-file references — none of which apply to a flat rule list today. The added tooling and learning curve are not justified.

Related: #20 (parent issue), #43.

## Decision

Use YAML as the configuration format for mcp-proxy policy rules, parsed with `gopkg.in/yaml.v3`.

Key reasons:

- **Human-readable and writable** — YAML's minimal syntax (no braces, no mandatory quoting for simple strings) makes rules scannable at a glance. Glob patterns like `delete_*` read naturally without escaping.
- **Comments are first-class** — operators can annotate rules with rationale or link to tickets, which is impossible in JSON.
- **Familiar to the target audience** — platform engineers already maintain YAML daily for Kubernetes manifests, Docker Compose files, CI pipelines, and Ansible playbooks. No new syntax to learn.
- **Sufficient for the rule model** — the policy schema is a flat list of structs with optional fields. YAML handles this cleanly with `omitempty` tags and no syntactic overhead.
- **Minimal dependency** — `gopkg.in/yaml.v3` is a single, well-maintained Go library. Unmarshalling directly into Go structs provides type-safe loading with no code generation or schema compilation step.
- **Static and auditable** — YAML files are plain text that can be reviewed in pull requests, diffed, linted, and version-controlled. There is no runtime evaluation or Turing-complete logic to reason about.

## Consequences

- Policy rules are decoupled from proxy code — the proxy uses built-in Go defaults unless a rules file is explicitly supplied via `--rules`. Operators can use the repository's example file at `mcp-proxy/configs/default_rules.yaml` as a starting point or provide their own, with no recompilation required.
- The rule format is intentionally simple: glob patterns, optional field matching, and a severity-ordered action. If future requirements demand cross-rule dependencies, computed fields, or conditional logic, YAML may become insufficient and this decision should be revisited (OPA/Rego would be the natural next step).
- YAML parsing quirks (the Norway problem, implicit type coercion) are somewhat constrained by decoding into typed Go structs, but `yaml.Unmarshal` is not strict by default — surprising coercions and silently ignored unknown fields are still possible unless explicit validation or strict decoding (e.g., `yaml.Decoder` with `KnownFields(true)`) is added.
- No schema validation beyond Go struct tags exists today. Adding a JSON Schema or validation step would improve error messages for malformed rule files.
- Contributors who are unfamiliar with YAML indentation rules may introduce subtle errors. A CI lint step (e.g., `yamllint`) would mitigate this.
