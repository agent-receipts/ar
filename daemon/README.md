# agent-receipts-daemon

Single OS-user process that owns the Ed25519 signing key and the SQLite
receipt store. Emitters (mcp-proxy, OpenClaw, SDK consumers) connect over a
local Unix-domain socket and send fire-and-forget event frames; the daemon
captures the connecting peer's OS-attested credentials, canonicalises the
receipt (RFC 8785), signs it (Ed25519), and persists it.

See [ADR-0010](../docs/adr/0010-daemon-process-separation.md) for design
rationale and [issue #236](https://github.com/agent-receipts/ar/issues/236)
for the work breakdown.

This is **Phase 1** of the daemon roll-out — the foundation slice. It ships
the standalone daemon binary, peer-cred capture, chain-tail resumption, and
the file-backed `KeySource`. Emitter refactor for mcp-proxy / OpenClaw / SDK
ships in later phases.

## Build

```sh
go build ./cmd/agent-receipts-daemon
go test ./...                     # unit tests
go test -tags=integration ./...   # integration tests (real socket, real DB)
```

Build from a clone of the monorepo: the repo-root `go.work` wires the in-tree
`sdk/go` so `go build` from `daemon/` picks up `ReceiptStore.GetChainTail`.

`go install github.com/agent-receipts/ar/daemon/cmd/agent-receipts-daemon@latest`
is **not yet supported**: the daemon depends on `sdk/go.GetChainTail`, which
is not in the latest published `sdk/go` tag (`v0.6.0`). Standalone install
becomes possible once the next `sdk/go` tag is released and a follow-up bumps
the require in `daemon/go.mod`.

### CI coverage

GitHub Actions workflow path filters in this repo currently target
`sdk/go/**`, `mcp-proxy/**`, etc. — none cover `daemon/**`. Until a
maintainer adds a `daemon.yml` workflow (AGENTS.md requires explicit human
review for any CI change), Phase 1 daemon changes rely on:

- The `mcp-proxy.yml` `sdk/go/**` trigger, which exercises the
  `GetChainTail` change but not the daemon module itself.
- Manual local verification per the *Build* section above (vet + tests with
  and without `-tags=integration`, plus `-race`).

The follow-up tracker in [#236](https://github.com/agent-receipts/ar/issues/236)
includes "add daemon CI workflow" alongside emitter refactor and packaging.

## Run

The daemon takes config from flags (preferred) or environment variables. All
fields have sensible per-OS defaults.

```sh
agent-receipts-daemon \
  --socket /run/agentreceipts/events.sock \
  --db    /var/lib/agentreceipts/receipts.db \
  --key   /etc/agentreceipts/signing.key \
  --chain-id default \
  --issuer-id "did:agent-receipts-daemon:$(hostname)" \
  --verification-method "did:agent-receipts-daemon:$(hostname)#k1"
```

| Flag | Env | Default |
|---|---|---|
| `--socket` | `AGENTRECEIPTS_SOCKET` | `/run/agentreceipts/events.sock` (Linux), `$TMPDIR/agentreceipts/events.sock` (macOS) |
| `--db` | `AGENTRECEIPTS_DB` | `~/.agent-receipts/receipts.db` |
| `--key` | `AGENTRECEIPTS_KEY` | `~/.agent-receipts/signing.key` |
| `--chain-id` | `AGENTRECEIPTS_CHAIN_ID` | `default` |
| `--issuer-id` | `AGENTRECEIPTS_ISSUER_ID` | `did:agent-receipts-daemon:local` |
| `--verification-method` | `AGENTRECEIPTS_VERIFICATION_METHOD` | `did:agent-receipts-daemon:local#k1` |

The signing key file must be a PKCS#8-encoded Ed25519 private key (the format
`receipt.GenerateKeyPair()` in `sdk/go` produces) with permissions no looser
than owner-only — the daemon rejects any group or world bit (read, write, or
execute), so `0600`, `0400`, etc. are accepted; `0640` and `0644` are not.
The daemon also refuses to start on a non-Ed25519 key, a symlink, or a
non-regular file at this path.

The socket directory is created with mode `0750` if missing; the socket
itself is `0660`. Phase 1 unprivileged installs use the per-user defaults
(`$TMPDIR` on macOS, `$XDG_RUNTIME_DIR` on Linux when set).

## Wire protocol

SOCK_STREAM Unix-domain socket (uniform across Linux and macOS — see
*Transport choice* below). Each emitter message is a 4-byte big-endian length
prefix followed by a JSON payload of that many bytes. Maximum payload is
1 MiB; larger frames are dropped with the connection.

The JSON payload is the ADR-0010 emitter schema:

```json
{
  "v": "1",
  "ts_emit": "2026-05-03T00:00:00.000Z",
  "session_id": "uuid-v4",
  "channel": "mcp_proxy",
  "tool": { "server": "github", "name": "list_repos" },
  "input": null,
  "output": null,
  "error": "",
  "decision": "allowed"
}
```

`decision` is one of `allowed` / `denied` / `pending`. The daemon adds
`seq`, `prev_hash`, `ts_recv`, peer attestation, and the receipt id before
signing, so emitters never see those fields and cannot forge them.

## Phase 1 scope and deviations

The following are deliberate Phase 1 choices, all callable out for follow-up:

- **Transport choice.** ADR-0010 specifies `SOCK_SEQPACKET`. macOS does not
  support SEQPACKET on AF_UNIX, so the daemon uses `SOCK_STREAM` uniformly
  on both Linux and macOS with explicit length-prefix framing. Peer-credential
  retrieval works identically on stream sockets, so the trust model is
  unchanged. A follow-up issue should amend ADR-0010 to record the per-OS
  socket type.
- **Peer attestation placement.** ADR-0010 calls for a top-level `peer`
  field on each receipt. Adding that requires a spec change (out of scope
  per AGENTS.md). Phase 1 stashes peer attestation in
  `action.parameters_disclosure` under keys `peer.platform`, `peer.pid`,
  `peer.uid`, `peer.gid`, `peer.exe_path`. The values are still
  signature-protected. The emitter-refactor phase will introduce the
  proper spec field.
- **macOS `peer.exe_path`.** Linux populates this from `/proc/<pid>/exe`.
  macOS leaves it empty in Phase 1 — `proc_pidpath` requires CGO or a raw
  libSystem syscall. Tracked for follow-up.
- **Single chain id.** The daemon owns one chain id per process. Multi-chain
  support can grow `chain.State` into a chainID-keyed map without breaking
  callers.
- **No emitter refactor.** mcp-proxy, OpenClaw, and the three SDKs continue
  to sign in-process. They will be migrated to thin emitters in Phase 2+.
- **No drop-counter / `events_dropped` synthetic receipts.** That mechanism
  belongs with the emitter side (`EAGAIN` handling) and ships with the
  emitter refactor.
- **No Homebrew / launchd / systemd packaging.** Operators run the binary
  directly in Phase 1.
- **No Windows port.** Tracked as a separate issue per #236.

## Layout

```
daemon.go                                  # Run() entrypoint and Config
cmd/agent-receipts-daemon/main.go          # CLI: flag/env parsing, signal handling
internal/
  chain/state.go                           # in-memory (seq, prev_hash) owner; sole writer
  keysource/keysource.go                   # KeySource interface (ADR-0015 shape)
  keysource/file.go                        # PEM-on-disk adapter
  socket/listener.go                       # Unix-domain socket + length-prefix framing
  socket/peercred_{linux,darwin,other}.go  # OS-specific peer-credential capture
  pipeline/build.go                        # frame + peer -> AgentReceipt -> sign -> store
integration_test.go                        # tags: integration. End-to-end concurrency + peer-cred fixture.
```
