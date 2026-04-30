# Site Technical Audit — SDK Install / Usage / Integration

**Scope:** Install commands, package names, version numbers, code samples, API
signatures, integration claims, CLI flags, and linked file paths for the Go,
TypeScript, and Python SDKs and the MCP proxy.  
**Out of scope:** Architecture (daemon vs in-process), crypto primitives
(Ed25519, RFC 8785, W3C VC).  
**Date:** 2026-04-30  
**Ground truth sources:** `sdk/go/go.mod`, `sdk/ts/package.json`,
`sdk/py/pyproject.toml`, `sdk/py/src/agent_receipts/`, `sdk/ts/src/`,
`sdk/go/`, `mcp-proxy/cmd/mcp-proxy/`.

---

## 1. Go SDK — `site/src/content/docs/sdk-go/installation.mdx`

### 1.1 Install command is correct

- **Site claim (line 9):** `go get github.com/agent-receipts/ar/sdk/go`
- **Ground truth:** `sdk/go/go.mod` line 1: `module github.com/agent-receipts/ar/sdk/go`
- **Verdict:** Correct.

### 1.2 Import paths in installation page are correct

- **Site claim (lines 15–19):** imports use `github.com/agent-receipts/ar/sdk/go/receipt` etc.
- **Verdict:** Matches `go.mod`. Correct.

### 1.3 Go SDK README uses wrong module path (out-of-band finding, not site)

- **SDK README (`sdk/go/README.md`) line 21:** `go get github.com/agent-receipts/sdk-go`
- **SDK README lines 41–43:** import paths `github.com/agent-receipts/sdk-go/receipt` etc.
- **Ground truth:** module path is `github.com/agent-receipts/ar/sdk/go`
- **Severity:** blocker (in the SDK README, not the site — noted for completeness because
  a user following the SDK README will get a broken install; the site itself is correct)

### 1.4 Node.js version claim — n/a for Go SDK

---

## 2. Go SDK — `site/src/content/docs/sdk-go/api-reference.mdx`

### 2.1 `AllActions()` — stale action count claim

- **Site claim (line 263):** `"Return all 15 built-in action types (filesystem and system categories)."`
- **Ground truth (`sdk/go/taxonomy/taxonomy.go`):** Three slices —
  `FilesystemActions` (7), `SystemActions` (7), `DataActions` (3) — total 17
  named types plus `UnknownAction`. `AllActions()` returns 18 entries.
- **Severity:** drift (description is stale; the function signature is correct)

### 2.2 `DataActions` variable not documented

- **Site:** The api-reference documents `FilesystemActions` (line not shown) but
  does not mention `DataActions` as a public variable.
- **Ground truth (`sdk/go/taxonomy/taxonomy.go` lines 58–62):**
  `DataActions` is an exported `var`.
- **Severity:** nit (omission, not a breakage)

---

## 3. TypeScript SDK — `site/src/content/docs/sdk-ts/installation.mdx`

### 3.1 Install command is correct

- **Site claim (line 9):** `npm install @agnt-rcpt/sdk-ts`
- **Ground truth:** `sdk/ts/package.json` line 2: `"name": "@agnt-rcpt/sdk-ts"`
- **Verdict:** Correct.

### 3.2 Node.js version requirement is stale

- **Site claim (line 20):** `- Node.js 18+`
- **Ground truth:** `sdk/ts/package.json` line 35: `"node": ">=22.11.0"`
- **Severity:** blocker (an install on Node 18–21 will fail the engine check;
  a copy-paste failure for users on older Node versions)

---

## 4. TypeScript SDK — `site/src/content/docs/sdk-ts/api-reference.mdx`

### 4.1 `SYSTEM_ACTIONS` count claim is wrong

- **Site claim (line 408):** `const SYSTEM_ACTIONS: readonly ActionTypeEntry[]  // 8 types`
- **Ground truth (`sdk/ts/src/taxonomy/actions.ts` lines 41–77):** 7 entries.
- **Severity:** drift (comment is wrong; the exported symbol itself is correct)

### 4.2 `DATA_ACTIONS` constant not documented

- **Site:** The "Built-in action registries" section (lines 407–410) lists only
  `FILESYSTEM_ACTIONS`, `SYSTEM_ACTIONS`, `ALL_ACTIONS`, and `UNKNOWN_ACTION`.
- **Ground truth (`sdk/ts/src/taxonomy/actions.ts` lines 79–95, line 124):**
  `DATA_ACTIONS` is exported.
- **Severity:** nit

### 4.3 `ReceiptStore` constructor documented as callable

- **Site claim (line 297):** `class ReceiptStore { constructor(dbPath: string); ... }`
- **Ground truth:** `openStore(dbPath)` is the public factory; `ReceiptStore` is the
  class type. Both are exported. The documented constructor call is valid but the
  preferred usage is `openStore`.
- **Severity:** nit

---

## 5. Python SDK — `site/src/content/docs/sdk-py/installation.mdx`

### 5.1 Install command is correct

- **Site claim (line 9):** `pip install agent-receipts`
- **Ground truth:** `sdk/py/pyproject.toml` line 6: `name = "agent-receipts"`
- **Verdict:** Correct.

---

## 6. Python SDK — `site/src/content/docs/sdk-py/overview.mdx`

### 6.1 `create_receipt` called with wrong calling convention — missing `chain` arg

- **Site claim (lines 23–34):**
  ```python
  receipt = create_receipt(
      issuer={"id": "did:agent:my-agent"},
      action={"type": "filesystem.file.read", "risk_level": "low"},
      principal={"id": "did:user:alice"},
      outcome={"status": "success"},
  )
  ```
- **Ground truth (`sdk/py/src/agent_receipts/receipt/create.py` line 59):**
  `def create_receipt(input: CreateReceiptInput) -> UnsignedAgentReceipt`
  The function takes a single positional `input` argument of type `CreateReceiptInput`.
  Calling `create_receipt(issuer=..., action=..., ...)` passes keyword arguments
  that don't match the parameter name `input` — Python raises `TypeError:
  create_receipt() got an unexpected keyword argument 'issuer'` at runtime.
  Additionally, `chain` (a required field in `CreateReceiptInput` with no default)
  is absent from the call.
- **Severity:** blocker (copy-paste fails with a `TypeError`)

### 6.2 `sign_receipt` called without required `verification_method` argument

- **Site claim (line 33):** `signed = sign_receipt(receipt, private_key)`
- **Ground truth (`sdk/py/src/agent_receipts/receipt/signing.py` lines 69–73):**
  ```python
  def sign_receipt(
      unsigned: UnsignedAgentReceipt,
      private_key: str,
      verification_method: str,
  ) -> AgentReceipt:
  ```
  `verification_method` is a required positional argument with no default.
  The two-argument call raises `TypeError: sign_receipt() missing 1 required
  positional argument: 'verification_method'`.
- **Severity:** blocker (copy-paste fails)

---

## 7. Python SDK — `site/src/content/docs/getting-started/quick-start.mdx` (Python section)

### 7.1 `create_receipt` called with wrong calling convention

- **Site claim (lines 95–110):**
  ```python
  unsigned = create_receipt(
      issuer={"id": "did:agent:my-agent"},
      principal={"id": "did:user:alice"},
      action={...},
      outcome={"status": "success"},
      chain={...},
  )
  ```
- **Ground truth:** same as §6.1 — `create_receipt` takes `input: CreateReceiptInput`,
  not keyword arguments. `create_receipt(issuer=...)` raises `TypeError`.
  (Note: `chain` is present here, unlike the overview page, but the calling
  convention is still wrong.)
- **Severity:** blocker

### 7.2 `sign_receipt` called without required `verification_method` argument

- **Site claim (line 111):** `receipt = sign_receipt(unsigned, keys.private_key)`
- **Ground truth:** same as §6.2 — `verification_method` is required.
- **Severity:** blocker

---

## 8. Python SDK — `site/src/content/docs/sdk-py/api-reference.mdx`

### 8.1 `SYSTEM_ACTIONS` count claim is wrong

- **Site claim (line 406):** `SYSTEM_ACTIONS: list[ActionTypeEntry]  # 8 types`
- **Ground truth (`sdk/py/src/agent_receipts/taxonomy/actions.py` lines 45–80):**
  7 entries.
- **Severity:** drift

### 8.2 `DATA_ACTIONS` not documented

- **Site:** "Built-in action registries" section (lines 405–408) omits `DATA_ACTIONS`.
- **Ground truth (`sdk/py/src/agent_receipts/taxonomy/actions.py` lines 83–96):**
  `DATA_ACTIONS` is a public module-level variable exported via `__init__.py`.
- **Severity:** nit

### 8.3 `VERSION` constant comment is stale

- **Site claim (line 259):** `VERSION: str  # "0.2.3"`
- **Ground truth (`sdk/py/src/agent_receipts/_version.py` line 1):**
  `VERSION = "0.2.2"`
- **Severity:** drift (stale but minor; the comment is informational only)

### 8.4 `sign_receipt` API reference signature is correct

- **Site claim (lines 30–35):** Shows `verification_method: str` as required —
  this matches the implementation.
- **Verdict:** Correct. The api-reference page is accurate; the blocker is only
  in the code samples on the overview and quick-start pages (§6–7).

---

## 9. MCP Proxy — `site/src/content/docs/mcp-proxy/installation.mdx`

### 9.1 Install commands are correct

- Homebrew: `brew install agent-receipts/tap/mcp-proxy` — matches `mcp-proxy/README.md` line 36.
- Source: `go install github.com/agent-receipts/ar/mcp-proxy/cmd/mcp-proxy@latest` — matches the module structure.
- **Verdict:** Correct.

### 9.2 Persistent key generation — site uses `openssl genpkey` instead of `mcp-proxy init`

- **Site claim (lines 74–75):**
  ```
  openssl genpkey -algorithm Ed25519 -out private.pem
  openssl pkey -in private.pem -pubout -out public.pem
  ```
- **Ground truth (`mcp-proxy/cmd/mcp-proxy/cli.go` `cmdInit`):**
  `mcp-proxy init -key <path>` generates the key pair, writes the private key
  to `<path>` (0600) and the public key to `<path>.pub` (0644). The README
  (`mcp-proxy/README.md` lines 98–100) documents this subcommand.
- The site installation page omits `mcp-proxy init` and shows the `openssl`
  path only. Both approaches produce valid keys, but the site does not mention
  the built-in `init` subcommand.
- **Severity:** drift (the `openssl` path works; `init` is not documented here
  at all, but `claude-desktop.mdx` and `claude-code.mdx` also use `openssl`)

### 9.3 `mcp-proxy -version` flag convention

- **Site claim (line 29):** `mcp-proxy -version`
- **Ground truth (`mcp-proxy/cmd/mcp-proxy/main.go` line 51):**
  `case "-version", "--version":` — both forms accepted.
- **Verdict:** Correct.

---

## 10. MCP Proxy — `site/src/content/docs/reference/cli-commands.mdx`

### 10.1 `mcp-proxy doctor` and `mcp-proxy audit-secrets` not documented

- **Ground truth (`mcp-proxy/cmd/mcp-proxy/main.go` lines 75–82):**
  Both `doctor` and `audit-secrets` are dispatched as subcommands. `doctor`
  reports policy config health; `audit-secrets` scans the audit database for
  leaked secrets. The `mcp-proxy/README.md` documents `audit-secrets` in full.
- **Site:** Neither subcommand appears in `reference/cli-commands.mdx`.
- **Severity:** drift (users who need `audit-secrets` will not find it on the site)

### 10.2 `mcp-proxy init` not documented in CLI reference

- **Ground truth:** `init` is a subcommand in `main.go` (line 76) and documented
  in `mcp-proxy/README.md` (lines 98–106).
- **Site:** `reference/cli-commands.mdx` does not include `mcp-proxy init`.
- **Severity:** drift

### 10.3 `mcp-proxy list` flags — mixed single/double dash

- **Site (lines 25–31):** `mcp-proxy list -risk high` (single dash) but
  line 31: `mcp-proxy list --follow --interval 1s` (double dash).
- **Ground truth:** Go's `flag` package accepts both `-flag` and `--flag`.
  Both work; the style inconsistency is a nit.
- **Severity:** nit

---

## 11. MCP Proxy — `site/src/content/docs/mcp-proxy/overview.mdx`

### 11.1 Quick start uses long-form flags inconsistently

- **Site claim (lines 62–66):**
  ```
  mcp-proxy \
    -name github \
    -key private.pem \
    -rules rules.yaml \
    -taxonomy taxonomy.json \
    github-mcp-server stdio
  ```
- **Ground truth:** `-key`, `-rules`, `-taxonomy`, `-name` are all valid (Go flag).
- **Verdict:** Correct.

---

## 12. MCP Proxy — `site/src/content/docs/mcp-proxy/claude-code.mdx` and `claude-desktop.mdx`

### 12.1 Key generation uses `openssl` throughout; `mcp-proxy init` not mentioned

- Both pages show the same `openssl genpkey` path as `installation.mdx`.
  Same note as §9.2 — workable but the built-in `init` subcommand is not surfaced.
- **Severity:** drift

### 12.2 All flags and JSON configs appear correct

- Flags `-name`, `-key`, `-issuer-name`, `-operator-id`, `-operator-name`,
  `-http`, `-chain` — all verified present in `main.go` `serve()`.
- `.mcp.json` and `claude_desktop_config.json` structure matches Claude's expected format.
- **Verdict:** Correct.

---

## 13. OpenClaw integration — `site/src/content/docs/openclaw/`

### 13.1 OpenClaw plugin does not exist in this repo

- **Site claim (`openclaw/overview.mdx` line 7):**
  "Repository: [agent-receipts/openclaw](https://github.com/agent-receipts/openclaw)"
- **Site claim (`openclaw/installation.mdx` line 6):**
  "The plugin is published to npm as [`@agnt-rcpt/openclaw`](https://www.npmjs.com/package/@agnt-rcpt/openclaw)."
- **Ground truth:** `find /home/user/ar -name "package.json" | xargs grep -l "openclaw"` — no
  results. No `sdk/openclaw/`, no `plugin/`, no `@agnt-rcpt/openclaw` package anywhere
  in the monorepo.
- The entire `site/src/content/docs/openclaw/` section (4 pages + blog post) describes
  a plugin that does not exist in this repository and may not be published to npm.
- **Severity:** blocker (install command `openclaw plugins install @agnt-rcpt/openclaw`
  references a package that cannot be verified to exist; all code samples and CLI
  references on these pages are unverifiable)

### 13.2 OpenClaw CLI reference uses old `parameters_preview` / `parameterPreview` names

- **Site claim (`openclaw/cli-reference.mdx` line 65):**
  ```
  | jq '.receipts[] | select(.parameters_preview.command | strings | contains("rm"))'
  ```
- **Site claim (lines 68–69):**
  "`parameters_preview` field is only populated when `parameterPreview` is enabled in the plugin config."
- **Site claim (line 69, link target):**
  `[Installation](/openclaw/installation/#parameter-preview)`
- **Ground truth (`openclaw/installation.mdx` lines 123–127):** The installation
  page explicitly states that `parameterPreview` was renamed to `parameterDisclosure`
  and `parameters_preview` was renamed to `parameters_disclosure` in the 0.6.0 SDK
  release, with no deprecation alias.
- The CLI reference page was not updated: uses the old field/config names, and
  links to anchor `#parameter-preview` which does not exist (the section heading is
  "## Parameter disclosure", resolving to `#parameter-disclosure`).
- **Severity:** blocker (broken anchor link; jq filter uses field name that no
  longer exists)

---

## 14. Cross-cutting issues

### C1. Python code samples systematically use wrong calling convention

All Python code samples on the site that call `create_receipt` directly pass
keyword arguments (`issuer=...`, `action=...`, etc.) instead of constructing a
`CreateReceiptInput` object. This is a runtime `TypeError`. Affected pages:
- `site/src/content/docs/getting-started/quick-start.mdx` lines 95–110
- `site/src/content/docs/sdk-py/overview.mdx` lines 23–34

The correct calling convention (used in `sdk/py/README.md` lines 72–85):
```python
unsigned = create_receipt(CreateReceiptInput(
    issuer=Issuer(id="did:agent:my-agent"),
    ...
))
```

### C2. Python `sign_receipt` samples systematically omit `verification_method`

All Python `sign_receipt` calls in site code samples use only two arguments,
missing the required third `verification_method: str` parameter. Affected pages:
- `site/src/content/docs/getting-started/quick-start.mdx` line 111
- `site/src/content/docs/sdk-py/overview.mdx` line 33

### C3. Action type count "15" is stale across all SDKs and the site

Every location that claims "15 built-in action types" is wrong: there are now
17 named types (7 filesystem + 7 system + 3 data.api.*) plus `unknown` = 18 in
`ALL_ACTIONS`. Affected:
- `site/src/content/docs/sdk-go/api-reference.mdx` line 263
- `site/src/content/docs/sdk-ts/api-reference.mdx` lines 408–409 (also says
  `SYSTEM_ACTIONS` is 8 types when it is 7)
- `site/src/content/docs/sdk-py/api-reference.mdx` lines 405–406 (same)
- `sdk/go/README.md` line 29, `sdk/ts/README.md` lines 192 and 213 (not site pages,
  but consistent drift)

### C4. `DATA_ACTIONS` constant undocumented in TS and Python api-references

Both `site/src/content/docs/sdk-ts/api-reference.mdx` and
`site/src/content/docs/sdk-py/api-reference.mdx` omit `DATA_ACTIONS` from
the "Built-in action registries" section, though the constant is exported by
both SDKs. This is partly what hides the count discrepancy (C3).

### C5. `mcp-proxy doctor` and `mcp-proxy audit-secrets` undocumented on site

Both are dispatched subcommands in `mcp-proxy/cmd/mcp-proxy/main.go` (lines
74–82). `audit-secrets` is documented in `mcp-proxy/README.md` with a full
flag reference; neither appears in `site/src/content/docs/reference/cli-commands.mdx`.

### C6. TypeScript SDK Node.js requirement on site is stale

`site/src/content/docs/sdk-ts/installation.mdx` line 20 says "Node.js 18+" but
`sdk/ts/package.json` line 35 requires `>=22.11.0`.

### C7. OpenClaw section references an unverifiable external package

The entire `site/src/content/docs/openclaw/` subtree (overview, installation,
agent-tools, cli-reference pages, and the blog deep-dive post) describes
`@agnt-rcpt/openclaw`, published at `github.com/agent-receipts/openclaw`.
Neither the package nor the repository exists within this monorepo. The install
instruction `openclaw plugins install @agnt-rcpt/openclaw` cannot be verified
to work. All code samples, config snippets, and CLI examples in those pages
are therefore unverifiable from this codebase. Treat the entire section as
aspirational / unverified unless an external repo is confirmed to exist and
be published.
