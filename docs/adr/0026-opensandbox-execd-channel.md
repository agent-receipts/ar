# ADR-0026: opensandbox_execd Emission Channel

## Status

Proposed — design note only. No implementation is in scope for this ADR.

## Context

### OpenSandbox as an AR integration surface

OpenSandbox (alibaba/OpenSandbox, CNCF Landscape) is a general-purpose agent
execution substrate. Agents run inside an isolated sandbox container; all
agent-initiated actions within the sandbox flow through a single in-sandbox
daemon: `execd`, a Gin HTTP service. This chokepoint property makes execd an
ideal AR instrumentation point — one hook, full coverage, no per-tool
integration work.

execd already exports OTLP metrics out-of-boundary, tagged with
`OPENSANDBOX_ID`. There is no tamper-evident record of what the agent did.
Agent Receipts fills that gap.

### execd action surface

| Endpoint | Action surface | Long-lived? |
|----------|----------------|-------------|
| `POST /command` | Shell command execution | No |
| `POST /code` (SSE) | Code execution; streams stdout/stderr until close | Yes (stream) |
| `GET/PUT/DELETE /files` | File read, write, delete | No |
| `GET/POST /directories` | Directory list, create | No |
| `POST /pty` | PTY session (interactive, long-running) | Yes (session) |

Every observable agent action inside the sandbox passes through one of these
five endpoints.

### OTLP is not sufficient

execd already emits OTLP metrics from the same post-action hook point. OTLP
covers the same actions — but OTLP is sampled, lossy, and produces metric
aggregates, not a complete ordered record of each individual action. Agent
Receipts requires:

- **Completeness.** Every action, not a sampled subset.
- **Ordering.** Hash-chained receipts with monotonic sequence numbers.
- **Tamper-evidence.** Ed25519 signature over the canonical receipt.

The AR emit hook uses a separate transport from OTLP. They share the same
instrumentation point in execd (a post-action callback) but share no
transport, delivery contract, or data model.

### Signing-key boundary

The Ed25519 signing key MUST NOT reside inside the sandbox. The sandbox is an
arbitrary-code environment for the agent; a key-in-sandbox is the CI-guide
colocation antipattern — signing from within the environment being audited.
The in-sandbox side is a keyless thin emitter: it serializes an unsigned event
frame and delivers it outbound to the host-side AR daemon. The daemon holds the
Ed25519 key, canonicalizes, signs, chains, and persists. This extends the
ADR-0010 daemon/emitter split across the sandbox/host boundary.

## Locked decisions

The following are fixed for this design note and must not be relitigated in
implementation issues:

1. **Key stays host-side.** execd's emit hook is keyless. The AR daemon on the
   host holds the Ed25519 key and produces all signatures.
2. **Two placement points, threat-model-mapped.** See §Placement table.
   Both are defined; deployments select based on their threat model.
3. **No new receipt format.** `opensandbox_execd` is an HttpEmitter consumer.
   The W3C VC envelope is unchanged.
4. **Separate transport from OTLP.** AR events use their own delivery path to
   the host daemon and share nothing with the OTLP exporter or its delivery
   contract.
5. **`OPENSANDBOX_ID` is the subject/binding field.** It appears in the
   receipt's `credentialSubject.binding.sandbox_id`, establishing the
   per-sandbox sub-chain.
6. **`/code` SSE receipts emit at stream close.** The event is canonicalized
   over `(code_hash, language, result_hash, logs_hash)` once the stream
   finishes, within execd's graceful-shutdown tail-drain window.

## Decision

### Channel value

`channel: "opensandbox_execd"`

The channel discriminator carries the trust statement: "this receipt was
produced by execd's AR emit hook inside an OpenSandbox sandbox; signing,
chaining, and storage happen host-side in the AR daemon." Verifiers reading the
channel value can look up this ADR's coverage envelope and apply the appropriate
trust calculus.

### Placement table

Two placement points are defined. They are complementary, not alternatives.
Placement A is the default and provides maximum action coverage under
honest-operator assumptions. Placement B is an optional add-on that provides
adversary-resistant coverage for boundary-crossing traffic.

| Property | Placement A — execd-side | Placement B — ingress/egress |
|---|---|---|
| **Where** | Inside the sandbox, as execd post-action middleware | Host-side network boundary (iptables/nftables hook, veth intercept, or CNI plugin) |
| **Covers** | All five execd endpoints | Boundary-crossing network actions only (outbound HTTP/S, DNS) initiated from `/command`, `/code`, and PTY sessions |
| **Recommended for** | Default; Wedge-C deployments proving to downstream consumers | High-assurance deployments where the agent may be adversarial; supplements Placement A |

**Threat-model mapping:**

| Threat | Placement A | Placement B |
|---|---|---|
| Agent lies about action parameters passed to execd | Not defended | Not defended |
| Operator modifies a receipt after signing | Defended | Defended |
| Legitimate operator suppresses receipts before the host daemon receives them | Not defended | Defended for network-crossing actions |
| Fully-compromised sandbox (sandbox root) suppresses emit | Not defended | Defended for network-crossing actions |
| Agent exfiltrates data over the network | Not defended unless via an execd endpoint | Defended |
| Agent reads the AR signing key | Defended — key never enters the sandbox | Defended |

The primary adversary Placement A defends against is an operator who controls the
host and sandbox configuration but cannot alter the receipt chain after it is
signed by the host daemon. Placement B adds adversary-resistant coverage for
network-crossing actions where even a compromised sandbox cannot suppress the
host network stack's observation.

### Action type mapping

execd endpoints map to existing AR taxonomy types where a match exists; new
types are proposed where none does. New types follow the established three-part
dotted pattern (`domain.subdomain.action`). Proposed new types require a
taxonomy amendment in the implementation PR.

#### `/command` → `system.command.execute`

Existing type. Risk: `high`.

| IPC field | Content |
|---|---|
| `action.type` | `system.command.execute` |
| `parameters_hash` | SHA-256 of canonical `{"command":<string>,"env":<map>?}` |
| `response_hash` | SHA-256 of canonical `{"exit_code":<int>}` |
| `binding.sandbox_id` | `OPENSANDBOX_ID` env var |
| `binding.endpoint` | `"/command"` |

#### `/code` → `system.code.execute` *(new type, risk: `high`)*

SSE endpoint. The emit hook fires once, after the stream closes (or after
execd's graceful-shutdown tail-drain window expires). If the sandbox is
force-terminated before the window expires, the receipt is lost; verifiers
treat the resulting gap as `incomplete_tool_roundtrip` per ADR-0019 O3.

| IPC field | Content |
|---|---|
| `action.type` | `system.code.execute` |
| `parameters_hash` | SHA-256 of canonical `{"code_hash":<sha256>,"language":<string>}` |
| `response_hash` | SHA-256 of canonical `{"result_hash":<sha256>,"logs_hash":<sha256>}` |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/code"` |

`code_hash` is SHA-256 of the submitted code text. `result_hash` and
`logs_hash` are SHA-256 of the accumulated SSE result and log streams
respectively. Raw code and outputs never appear in the receipt.

#### `/files` → `filesystem.file.*`

HTTP method determines the subtype. All four subtypes are existing taxonomy
types.

| HTTP method | `action.type` | Risk |
|---|---|---|
| `GET` | `filesystem.file.read` | `low` |
| `POST` | `filesystem.file.create` | `low` |
| `PUT` | `filesystem.file.modify` | `medium` |
| `DELETE` | `filesystem.file.delete` | `high` |

| IPC field | Content |
|---|---|
| `parameters_hash` | SHA-256 of canonical `{"path":<string>}` (read/delete) or `{"path":<string>,"content_hash":<sha256>}` (create/modify) |
| `response_hash` | SHA-256 of canonical `{"content_hash":<sha256>}` (read) or `{"bytes_written":<int>}` (create/modify) or `{}` (delete) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/files"` |

#### `/directories` → `filesystem.directory.*`

`filesystem.directory.create` exists. `filesystem.directory.list` is new
(risk: `low`).

| HTTP method | `action.type` | Risk |
|---|---|---|
| `GET` | `filesystem.directory.list` *(new)* | `low` |
| `POST` | `filesystem.directory.create` | `low` |

| IPC field | Content |
|---|---|
| `parameters_hash` | SHA-256 of canonical `{"path":<string>}` |
| `response_hash` | SHA-256 of canonical `{"entries_hash":<sha256>}` (list) or `{}` (create) |
| `binding.sandbox_id` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/directories"` |

#### `/pty` → `system.pty.open` / `system.pty.close` *(both new, risk: `critical`)*

PTY sessions are long-running and have no predictable end time. A single receipt
at session end would suppress evidence of a session running for hours. Two
receipts are emitted per PTY session:

1. **`system.pty.open`** — emitted when the PTY is established.
2. **`system.pty.close`** — emitted when the PTY closes (SIGHUP, client
   disconnect, or timeout). Linked to the open receipt via a `correlator` field
   (same pattern as `tool_use_id` in ADR-0013). A `pty.open` without a
   corresponding `pty.close` (abnormal termination, OOM kill, sandbox
   force-stop) is classified as `incomplete_session`.

| IPC field | `system.pty.open` | `system.pty.close` |
|---|---|---|
| `parameters_hash` | SHA-256 of canonical `{"command":<string>,"env":<map>?}` | SHA-256 of canonical `{"correlator":<string>}` |
| `response_hash` | SHA-256 of canonical `{"pty_id":<string>}` | SHA-256 of canonical `{"exit_code":<int>,"io_hash":<sha256>}` |
| `correlator` | Generated per-session UUID | Same UUID |
| `binding.sandbox_id` | `OPENSANDBOX_ID` | `OPENSANDBOX_ID` |
| `binding.endpoint` | `"/pty"` | `"/pty"` |

`io_hash` is SHA-256 of the accumulated PTY I/O stream. Raw I/O is not
persisted.

### `OPENSANDBOX_ID` as sub-chain scope

`OPENSANDBOX_ID` is injected by the sandbox orchestrator into the execd process
environment before execd starts. The agent cannot set or alter it.

In receipts, it appears as `credentialSubject.binding.sandbox_id`. It
establishes the sub-chain scope: all receipts from within a single sandbox
instance share the same `sandbox_id` and are sequenced together into a
sub-chain.

### Per-sandbox sub-chain anchored to the global chain

Receipts from within a single sandbox form a **sub-chain**: each receipt links
to its predecessor within that sandbox via `previousReceiptHash`. The sub-chain
is independently verifiable — its internal hash linkage and signatures are
self-contained.

The sub-chain's first receipt carries a `parentChainRef` field pointing to the
current tip of the host daemon's global chain at the moment the sub-chain is
initialized (i.e., when the first event for a new `OPENSANDBOX_ID` arrives at
the daemon). This anchoring provides:

1. **Global temporal ordering.** Sandbox `sid-abc` started "after global receipt
   N." Multiple concurrent sandboxes are ordered relative to each other via
   their anchor points in the global chain.
2. **Sub-chain completeness.** All events within `sid-abc` form a contiguous
   hash-linked sequence; a sequence gap within the sub-chain is a verification
   failure (per ADR-0019 P5).
3. **Cross-sandbox correlation.** Verifiers can locate a sandbox's sub-chain in
   the global sequence, enabling session-level audit scoping without scanning
   the entire chain.

Independent sub-chains (not anchored to the global chain) lose the temporal
ordering property across sandboxes and cannot be placed in the audit timeline.
Anchoring is required.

**Replication note.** In a replicated daemon deployment (future work per
ADR-0022), `parentChainRef` MUST be resolved against the current primary
replica at sub-chain initialization time to avoid anchor ambiguity. This is a
daemon-side concern not resolved in this ADR.

### Emit hook position relative to the OTLP exporter

```
execd request handler
       │
       ▼  (action processing)
       │
       ├─► [OTLP middleware]  ──► OTLP collector
       │      (existing)            sampled, metric aggregates, lossy
       │
       └─► [AR emit hook]     ──► AR daemon (host)
              (new)                 complete, ordered, signed
```

Both hooks register as post-action callbacks at the same execd lifecycle point.
They share no state, no transport, and no delivery contract. The AR emit hook
fires after the action completes (or, for SSE endpoints, after the stream
closes) and serializes an unsigned AR event frame to the host daemon over
outbound HTTPS.

### Transport from execd to the AR daemon

- **Path.** Outbound HTTPS from inside the sandbox to the AR daemon on the
  host. The sandbox network namespace permits outbound connectivity to a
  designated host address.
- **Auth strategy.** `mtls` (ADR-0020 HttpEmitter). execd presents a
  sandbox-instance TLS client certificate provisioned by the orchestrator. The
  daemon validates it before accepting an event frame.
- **On failure.** Per ADR-0025, transport failure MUST be surfaced. execd logs
  the failure at `ERROR` level. A failed emit does not abort the action — the
  action has already completed. Monitoring failed emits is an operator
  responsibility.
- **No dependency on open issues.** This design assumes HttpEmitter is
  functional as specified in ADR-0020. It does not require changes to
  HttpEmitter, idempotency keys (#480), or any other in-progress issues
  (#487, #533). Those are orthogonal.

### Sequence diagram

```
Agent (inside sandbox)
  │
  │  HTTP action request
  ▼
execd (inside sandbox, Gin HTTP daemon)
  │
  ├─► [OTLP middleware] ─────────► OTLP collector
  │      (existing)                  sampled, aggregated, lossy
  │
  │  Serialize unsigned AR event frame
  │  (OPENSANDBOX_ID bound; no key material)
  │
  │  POST /ingest (mTLS outbound)
  ▼
AR daemon (host-side)
  │
  ├─ Validate mTLS client cert
  ├─ Receive and validate event frame
  ├─ Canonicalize (RFC 8785, ADR-0002)
  ├─ Hash parameters + response (ADR-0008)
  ├─ Sign (Ed25519, ADR-0001)
  ├─ Chain (prev_hash, sub-chain scoped by sandbox_id)
  ├─ Persist (SQLite, ADR-0004)
  │
  └─► External anchor (ADR-0015, optional)
           rotation events + checkpoint hashes
```

The agent never communicates with the AR daemon. execd's emit hook is the sole
outbound path for AR event frames; the daemon's signing key is unreachable from
inside the sandbox.

### Machine-readable coverage metadata

Following ADR-0014, each `opensandbox_execd` receipt carries a `coverage` block
in the signed event body. The daemon canonicalizes and signs it alongside the
rest of the event, so the coverage claim is attested.

| Field | Type | Placement A | Placement B |
|---|---|---|---|
| `covers` | array of strings | `["command","code","files","directories","pty"]` | `["network_egress"]` |
| `excludes` | array of strings | `[]` | `["command","code","files","directories","pty"]` |
| `placement` | string | `"execd"` | `"ingress_egress"` |
| `opensandbox_version` | string | running version | running version |

The `coverage` block is emitter-asserted and not validated against ground truth
by the daemon. The daemon attests who sent the claim and that it has not been
tampered with post-signing; it cannot verify whether execd's hook integration
actually covers the stated surface on this host. Trust in the coverage claim is
bounded by trust in the binary that produced it — the same caveat as ADR-0014.

### Non-goals confirmed

- No execd fork. The emit hook is instrumentation added to a deployment of
  execd, not a change to execd's source.
- No OpenClaw-specific implementation. OpenClaw is the test bed; this design is
  substrate-agnostic.
- No OSEP authoring. If upstreaming the emit hook point proves valuable, a
  separate OSEP follow-up may be warranted; this ADR makes no upstream claim.
- No production deployment.
- No dependency on #487, #480, or #533.

## Consequences

### Easier

- OpenSandbox deployments gain a tamper-evident record of all in-sandbox agent
  actions at the single chokepoint without forking execd.
- The existing AR daemon, HttpEmitter (`mtls` strategy), and VC envelope are
  reused unchanged. No new receipt format, no new signing algorithm.
- Per-sandbox sub-chains scope audit evidence to individual sandbox runs;
  auditors reconstruct what happened in `sid-abc` without parsing the entire
  global chain.
- Placement B provides adversary-resistant receipts for boundary-crossing
  traffic — a property no existing channel offers.

### More difficult / costs

- **Placement A trust is honest-operator only.** A fully-compromised sandbox
  (sandbox root) can suppress or manipulate emit before the event reaches the
  AR daemon. This is the same "lying client" threat as `mcp_proxy` and
  `claude_code_hook`.
- **mTLS certificate lifecycle.** Each sandbox instance needs a client
  certificate. Provisioning, rotation, and revocation for ephemeral sandboxes
  is an operational concern not addressed in this ADR; a separate design note
  is needed.
- **`/code` tail-drain timing.** If the sandbox is force-terminated before
  execd's graceful-shutdown window completes, the `/code` receipt is lost.
  execd's SIGTERM handler must cooperate for the emit to succeed.
- **PTY open-without-close.** Abnormally terminated PTY sessions leave a
  `system.pty.open` receipt without a corresponding `system.pty.close`.
  Verifiers MUST classify this as `incomplete_session`, analogous to
  ADR-0019's `incomplete_tool_roundtrip`.
- **Taxonomy extensions required.** Three new action types
  (`system.code.execute`, `system.pty.open`, `system.pty.close`) and one new
  filesystem type (`filesystem.directory.list`) must be added to the taxonomy
  in the implementation PR.
- **`parentChainRef` field** is not yet defined in the daemon IPC contract.
  A subsequent ADR or daemon IPC amendment is needed to formalize sub-chain
  anchoring.

### Spawned follow-up work

1. [ ] Certificate provisioning strategy for ephemeral sandbox mTLS — separate
       design note; not in scope here.
2. [ ] Add `filesystem.directory.list`, `system.code.execute`,
       `system.pty.open`, `system.pty.close` to the taxonomy
       (`sdk/go/taxonomy/taxonomy.go` and the embedded taxonomy JSON in
       mcp-proxy).
3. [ ] Define `parentChainRef` in the daemon IPC contract; amend ADR-0010 or
       issue a targeted daemon-IPC ADR.
4. [ ] Verifier: classify `pty.open` without `pty.close` as
       `incomplete_session`; classify lost `/code` receipts as
       `incomplete_tool_roundtrip`.
5. [ ] Implementation: execd emit hook (Go middleware, wires HttpEmitter with
       `mtls` auth strategy).
6. [ ] Consider upstreaming the execd emit hook point to OpenSandbox if
       adoption warrants it — separate OSEP follow-up.

## Related ADRs

- [ADR-0010 (Daemon Process Separation)](./0010-daemon-process-separation.md) —
  defines the thin-emitter/daemon split and IPC contract this channel extends
  across the sandbox/host boundary.
- [ADR-0013 (`claude_code_hook`)](./0013-claude-code-hook-channel.md) — peer
  channel; establishes the `correlator`/`tool_use_id` pattern reused for PTY
  open/close pairing.
- [ADR-0014 (`codex_hook`)](./0014-codex-hook-channel.md) — peer channel;
  originator of the per-receipt `coverage` block schema this ADR reuses.
- [ADR-0019 (Protocol Integrity Gaps)](./0019-protocol-integrity-gaps-and-mitigations.md) —
  `incomplete_tool_roundtrip` and `incomplete_session` classification applied
  to `/code` stream loss and PTY open-without-close.
- [ADR-0020 (Emitter Abstraction)](./0020-emitter-abstraction-and-remote-receipt-delivery.md) —
  HttpEmitter with `mtls` auth strategy is the assumed outbound transport.
- [ADR-0025 (Emit Failure Contract)](./0025-emit-failure-contract.md) — emit
  failures MUST be surfaced; this ADR inherits that requirement.
