# ADR-0010: Daemon Process Separation for Signing and Storage

## Status

Accepted (2026-05-03). Phase 1 implementation lands the standalone daemon, peer-credential capture, the file-backed `KeySource`, and the `GetChainTail` store primitive. Emitter refactor (mcp-proxy, OpenClaw, three SDKs), packaging (Homebrew / launchd / systemd), and the Windows port follow in subsequent phases tracked under [issue #236](https://github.com/agent-receipts/ar/issues/236).

## Context

The current architecture runs the agent-receipts plugin/SDK in-process with the agent. This means the agent process owns the Ed25519 signing keys and has read/write access to the SQLite receipts database. An agent auditing itself is not a meaningful audit: a compromised or misbehaving agent can forge, suppress, or tamper with its own receipts. This undermines the core value proposition of tamper-evident receipts.

A secondary problem: every emitter (each MCP proxy instance, each OpenClaw-using agent, each SDK consumer) currently carries its own copy of the keypair in memory, its own SQLite connection and WAL, its own RFC 8785 canonicalizer, and its own hash-chain state. Running multiple MCP proxies plus an agent session means N independent crypto/storage stacks doing the same job, with N separate chains that share no sequence space — making cross-channel correlation a query-time problem rather than a structural property.

## Decision

Split every integration into two roles:

1. **Thin emitter** — the plugin, proxy, or SDK fires an event describing the tool call. No signing, no storage, no crypto. Fire-and-forget over a local IPC socket. The agent must never block waiting for the audit layer. Two failure modes are distinguished, with deliberately different visibility properties:
   - **Daemon not running** (connect fails or is refused): events truly drop silently. There is no daemon to record the gap, by definition. Operators detect this via the absence of fresh receipts and via service-manager status, not via in-chain signal.
   - **Daemon running but backpressured** (`EAGAIN` on a non-blocking send): drops are tracked and surface in the chain via the `events_dropped` mechanism described under *Permissions and trust* below.

2. **agent-receipts daemon** — a separate process running as its own OS user, sole owner of the signing keys and the SQLite database. Receives events, captures peer credentials, canonicalizes (RFC 8785), hash-chains, signs (Ed25519), and persists.

### IPC transport

- Linux: Unix domain socket (`SOCK_SEQPACKET`) at `/run/agentreceipts/events.sock`.
- macOS: Unix domain socket (`SOCK_SEQPACKET`) at `/var/run/agentreceipts/events.sock` (which resolves to `/private/var/run/agentreceipts/events.sock`).
- Windows: named pipe via Node's `net` module (`\\.\pipe\agentreceipts-events`) with equivalent ACL semantics.
- Socket and pipe locations are configurable; unprivileged installs override the default (e.g. `$XDG_RUNTIME_DIR/agentreceipts/events.sock`).
- TCP loopback is explicitly rejected — it dissolves the filesystem permission model and would require a bespoke local auth scheme.
- `SOCK_SEQPACKET` is chosen over `SOCK_DGRAM` so peer credentials are reliably retrievable at the OS level — datagram sockets either lack a defined cred mechanism or require per-message ancillary data with platform-specific gaps — and over `SOCK_STREAM` so each event remains a discrete message without length-prefix framing.

### Permissions and trust

- Daemon is the sole writer to the database and key store.
- Emitters cannot read the database or keys.
- Daemon captures peer credentials at connection-accept time, using the connected-socket primitive native to each platform:
  - Linux: `SO_PEERCRED` for `uid`, `gid`, `pid`.
  - macOS: `LOCAL_PEERCRED` for `uid` and `gid`; `LOCAL_PEEREPID` for `pid`.
  - Windows: `GetNamedPipeClientProcessId` for `pid`; `OpenProcessToken` to extract the user SID and integrity level.
  The executable path is read from `/proc/<pid>/exe` (Linux), `proc_pidpath` (macOS), or `QueryFullProcessImageName` (Windows). The agent's self-asserted identity is untrusted; peer attestation is what makes the audit meaningful.
- Connection is non-blocking. When the daemon's per-connection receive buffer is full, the emitter's send returns `EAGAIN`; the emitter increments a local drop counter rather than blocking, and flushes the counter alongside its next successful event. The daemon records the gap as a synthesised `events_dropped` receipt in the chain so dropped events are never invisible. (One narrow loss window remains — the emitter crashing after dropping but before flushing — and is documented as such.)

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
- `peer` — platform-tagged identity object. Common across all platforms: `platform` (`linux` | `darwin` | `windows`), `pid`, `exe_path`. POSIX (`linux`, `darwin`) additionally carries `uid`, `gid`. Windows additionally carries `user_sid` and `integrity_level`. The `platform` discriminator is authoritative for which identity fields are present; verifiers MUST NOT collapse Windows SIDs into numeric uids.
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

- [ADR-0001 (Ed25519 signing)](./0001-ed25519-for-receipt-signing.md) — unchanged, but the key now lives only in the daemon.
- [ADR-0002 (RFC 8785 canonicalization)](./0002-rfc8785-json-canonicalization.md) — moves exclusively to the daemon.
- [ADR-0004 (SQLite storage)](./0004-sqlite-for-local-receipt-storage.md) — daemon is sole writer; readers use filesystem permissions.
