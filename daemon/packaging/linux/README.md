# Linux systemd packaging for agent-receipts-daemon

Two unit files are provided:

| File | Target | Use case |
|------|--------|----------|
| `agent-receipts-daemon.service` | `~/.config/systemd/user/` | Per-user install — no root required |
| `agent-receipts-daemon.system.service` | `/etc/systemd/system/` | System-wide install with a dedicated service user |

---

## User-level install (recommended for beta)

Runs as the logged-in user. No root or dedicated system user needed. Data lives in the user's home directory.

### Prerequisites

Install the binary (pick one):

```sh
# Via go install (once sdk/go v0.7+ is tagged):
go install github.com/agent-receipts/ar/daemon/cmd/agent-receipts-daemon@latest

# Or build from source:
git clone https://github.com/agent-receipts/ar
cd ar/daemon
go build -o ~/.local/bin/agent-receipts-daemon ./cmd/agent-receipts-daemon
```

The unit file assumes `~/.local/bin/agent-receipts-daemon` (`%h/.local/bin/…`). If the binary is elsewhere, edit `ExecStart` before installing the unit.

### 1 — Generate the signing key (once)

```sh
agent-receipts-daemon -init
```

This creates `~/.local/share/agent-receipts/signing.key` (0600) and
`~/.local/share/agent-receipts/signing.key.pub` (0644). The daemon refuses to
start without a key. Run `-init` only once; re-running it overwrites the key
and invalidates any existing receipt chain.

> **Note:** the default key and database paths have recently moved to
> `~/.local/share/agent-receipts/` (XDG Base Directory). If you ran an earlier
> beta that wrote to `~/.agent-receipts/`, pass `-key` and `-db` flags or the
> corresponding environment variables to point the daemon at the old paths, or
> move the files to the new location.

### 2 — Install and start the unit

```sh
mkdir -p ~/.config/systemd/user
cp agent-receipts-daemon.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now agent-receipts-daemon
```

### 3 — Check status and logs

```sh
systemctl --user status agent-receipts-daemon
journalctl --user -u agent-receipts-daemon -f
```

### Stopping / disabling

```sh
systemctl --user stop agent-receipts-daemon
systemctl --user disable agent-receipts-daemon
```

---

## System-level install (production)

Runs as a dedicated `agentreceipts` system user with restricted filesystem permissions and seccomp-style systemd hardening.

### Prerequisites

Install the binary to `/usr/local/bin/`:

```sh
# Build from source, then:
install -m 0755 agent-receipts-daemon /usr/local/bin/
```

### 1 — Create the `agentreceipts` user/group

**Option A — via systemd-sysusers (preferred on systemd distros):**

```sh
cp agent-receipts-daemon.system.sysusers /etc/sysusers.d/agent-receipts.conf
systemd-sysusers /etc/sysusers.d/agent-receipts.conf
```

> **Note:** `StateDirectory=agent-receipts` in the unit file causes systemd to create
> `/var/lib/agent-receipts` (owned by `agentreceipts`) on the first service start. If
> you use the sysusers approach, you do **not** need to create this directory manually.

**Option B — manually:**

```sh
useradd --system --no-create-home \
        --home-dir /var/lib/agent-receipts \
        --comment "Agent Receipts daemon" \
        --shell /usr/sbin/nologin \
        agentreceipts
```

### 2 — Generate the signing key (once)

The key must exist before the service first starts. Generate it as root and hand it to the service user:

```sh
# Create the config directory (systemd will also do this on first start, but
# we need it to exist before we write the key).
install -d -m 0750 -o agentreceipts -g agentreceipts /etc/agent-receipts

# Generate the key as the service user so ownership is correct from the start.
sudo -u agentreceipts \
  agent-receipts-daemon \
    -init \
    -key /etc/agent-receipts/signing.key \
    -db /var/lib/agent-receipts/receipts.db
```

The `-init` command writes `signing.key` (0600) and `signing.key.pub` (0644).

### 3 — Install and start the unit

```sh
cp agent-receipts-daemon.system.service /etc/systemd/system/agent-receipts-daemon.service

systemctl daemon-reload
systemctl enable --now agent-receipts-daemon
```

### 4 — Check status and logs

```sh
systemctl status agent-receipts-daemon
journalctl -u agent-receipts-daemon -f
```

### Stopping / disabling

```sh
systemctl stop agent-receipts-daemon
systemctl disable agent-receipts-daemon
```

---

## Socket path and emitter discovery

The daemon listens on a Unix-domain socket. Emitters (mcp-proxy, SDK consumers) connect to it to submit event frames.

| Install type | Default socket path |
|---|---|
| User-level | `$XDG_RUNTIME_DIR/agentreceipts/events.sock` (falls back to `/run/agentreceipts/events.sock`) |
| System-level | `/run/agentreceipts/events.sock` (set explicitly via `-socket`) |

Override at runtime:

```sh
# Daemon side:
agent-receipts-daemon -socket /custom/path/events.sock
# or:
AGENTRECEIPTS_SOCKET=/custom/path/events.sock agent-receipts-daemon

# Emitter side (mcp-proxy or SDK):
AGENTRECEIPTS_SOCKET=/custom/path/events.sock mcp-proxy ...
```

For the system-level unit, the socket lives under `/run/agentreceipts/` which `RuntimeDirectory=agentreceipts` creates (mode 0750, owned by `agentreceipts`). Emitter processes that need to connect must run as the `agentreceipts` user **or** be added to the `agentreceipts` group:

```sh
usermod -aG agentreceipts <emitter-user>
```

The socket itself is created with mode `0660` (owner `agentreceipts`, group `agentreceipts`), so group members can connect.

---

## Verifying the receipt chain

The `agent-receipts verify` CLI reads the SQLite store directly (read-only, safe to run while the daemon is running):

```sh
# User-level (uses default paths):
agent-receipts verify

# System-level (explicit paths):
agent-receipts verify \
  -db /var/lib/agent-receipts/receipts.db \
  -public-key /etc/agent-receipts/signing.key.pub \
  -chain-id default
```

Exit codes: `0` = verified, `1` = chain failed verification, `2` = usage error.
