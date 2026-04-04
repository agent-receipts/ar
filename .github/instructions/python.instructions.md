---
applyTo: "sdk/py/**"
---

# Python SDK review guidelines

- Prefer `from __future__ import annotations` in new or heavily-typed modules.
- Pydantic v2 for receipt models, frozen dataclasses for simple types.
- Use `TYPE_CHECKING` guards for type-only imports.
- Ruff for lint and format (line-length 88). Flag lines exceeding this.
- Tests mirror `src/` structure under `tests/`. Flag tests placed elsewhere.
- Output must be byte-identical to the TypeScript SDK.
