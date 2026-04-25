# ADR-0010: Daemon Process Separation for Signing and Storage

## Status

Proposed

## Context

The current architecture runs the agent-receipts plugin/SDK in-process with the agent. This means the agent process owns the Ed25519 signing keys and has read/write access to the SQLite receipts database. An agent auditing itself is not a meaningful audit: a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts. This undermines the core value proposition of tamper-evident receipts.

A secondary problem: every emitter (each MCP proxy instance, each OpenClaw-using agent, each SDK consumer) currently carries its own copy of the keypair in memory, its own SQLite connection and WAL, its own RFC 8785 canonicalizer, and its own hash-chain state. Running multiple MCP proxies plus an agent session means N independent crypto/storage stacks doing the same job, with N separate chains that share no sequence space — making cross-channel correlation a query-time problem rather than a structural property.

## Decision

Split every integration into two roles:

1. **Thin emitter** — the plugin, proxy, or SDK fires an event describing the tool call. No signing, no storage, no crypto. Fire-and-forget over a local IPC socket. If the daemon is not running, events drop silently — the agent must never block waiting for the audit layer.

2. **agent-receipts daemon** — a separate process running as its own OS user, sole owner of the signing keys and the SQLite database. Receives events, captures peer credentials, canonicalizes (RFC 8785), hash-chains, signs (Ed25519), and persists.

### IPC transport

- Linux/macOS: Unix domain socket (`SOCK_DGRAM`) at `/run/agentreceipts/events.sock`.
- Windows: named pipe via Node's `net` module (`\\.\pipe\agentreceipts-events`) with equivalent ACL semantics.
- TCP loopback is explicitly rejected — it dissolves the filesystem permission model and would require a bespoke local auth scheme.

### Permissions and trust

- Daemon is the sole writer to the database and key store.
- Emitters cannot read the database or keys.
- Daemon captures peer credentials (`SO_PEERCRED` on Linux/macOS; `GetNamedPipeClientProcessId` + `OpenProcessToken` on Windows) and records `uid`, `gid`, `pid`, `exe_path` on every receipt. The agent's self-asserted identity is untrusted; peer attestation is what makes the audit meaningful.
- Socket is non-blocking. Kernel drops on overflow are detected (`SO_RXQ_OVFL` on Linux) and recorded as synthesised `events_dropped` receipts in the chain so gaps are never invisible.

### Schema split

Emitter sends the minimum faithful representation:

- `v` (schema version)
- `ts_emit` (RFC 3339, advisory)
- `session_id` (UUID, scopes one agent run)
- `channel` (`openclaw` | `mcp_proxy` | `sdk` | ...)
- `tool` (`{ server, name }` for MCP; equivalent shape for other channels)
- `input`, `output`, `error` (raw, no normalisation)
- `decision` (`allowed` | `denied` | `pending`)

Daemon adds before signing:

- `seq`, `prev_hash`, `ts_recv` (authoritative)
- `peer` (`{ uid, gid, pid, exe_path }`)
- `id` (receipt UUID)

Canonicalization happens only in the daemon. Pre-canonicalizing in N emitters in N languages would silently break verification.

### Read interface

Filesystem-first, journald-style. The daemon owns writes and keys exclusively; reads happen via direct SQLite access with filesystem permissions:

- DB: `0640`, owner `agentreceipts`, group `agentreceipts-read`
- Public key: `0644`, world-readable
- The `agent-receipts verify` CLI reads the DB and public key directly and works when the daemon is down. The daemon is the only thing that can write, never the only thing that can read — independent verifiability is the property signing exists to provide.

A future read socket for live-tail (`agent-receipts tail -f`) is in scope but not part of this ADR.

## Consequences

### Positive

- Restores the audit property: an agent cannot forge, suppress, or tamper with its own receipts.
- Single chain across all channels (OpenClaw, MCP proxy, SDK) with monotonic `seq` and `session_id` grouping — directly addresses the unified cross-channel audit gap identified in the agent security landscape.
- Memory footprint per emitter drops to near-nothing (no keypair, no SQLite, no canonicalizer in-process). Multiple MCP proxies plus an agent session share one daemon.
- Faster emitter startup, especially for short-lived SDK consumers that currently pay the SQLite-open cost per run.
- Single canonicalizer eliminates a class of cross-language verification bugs.
- Simpler verification: one DB, one chain, one public key.
- Capability separation matches the trust model that mature projects in this space (e.g. Pipelock) use as a selling point.

### Negative / tradeoffs

- Adds an installable system service. Packaging story required: Homebrew formula, `.deb`/`.rpm` with systemd unit, launchd plist, Windows Service installer. This is friction the current `npm install` story does not have.
- Hard cutover for emitters. v1 in-process behaviour is deprecated and removed rather than left available, because shipping the "agent signs its own receipts" footgun under the agent-receipts name is worse than a major version bump. `@agnt-rcpt/openclaw` and the MCP proxy each become v2 with the daemon as a runtime requirement.
- The MCP proxy gains a two-layer attestation model (proxy attests in the event body to the connecting agent's PID/UID; daemon attests via peer creds to the proxy itself). Both are recorded; verifiers see both.
- Operators must run and supervise the daemon. Mitigated by standard service-manager integration on each platform.

## Related ADRs

- ADR-0001 (Ed25519 signing) — unchanged, but the key now lives only in the daemon.
- ADR-0002 (RFC 8785 canonicalization) — moves exclusively to the daemon.
- ADR-0004 (SQLite storage) — daemon is sole writer; readers use filesystem permissions.
