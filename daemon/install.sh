#!/bin/sh
# install.sh — user-level install for agent-receipts-daemon on Linux.
# Usage: curl -fsSL https://github.com/agent-receipts/ar/releases/latest/download/install.sh | sh
#
# Installs to ~/.local/bin, sets up the systemd user unit, and generates the
# signing key if one does not already exist. Safe to re-run for upgrades.
set -eu

REPO="agent-receipts/ar"
INSTALL_DIR="${HOME}/.local/bin"
KEY_FILE="${HOME}/.local/share/agent-receipts/signing.key"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_NAME="agent-receipts-daemon.service"
BASHRC="${HOME}/.bashrc"

step() { printf '\n==> %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# Linux only
[ "$(uname -s)" = "Linux" ] || die "Linux only. For macOS: brew install agent-receipts/tap/agent-receipts-daemon"

# Require systemd
command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this installer requires systemd"

# Map uname -m to GoReleaser arch labels
case "$(uname -m)" in
  x86_64)        GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *)             die "Unsupported architecture: $(uname -m)" ;;
esac

# Resolve latest daemon release from the GitHub releases API.
# The repo contains multiple components with distinct tag prefixes (sdk/go/v*,
# mcp-proxy/v*, daemon/v*) so we filter specifically for daemon tags rather
# than relying on the repo-wide "latest" release pointer.
step "Resolving latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
  | grep '"tag_name"' \
  | grep '"daemon/v' \
  | head -1 \
  | sed 's/.*"daemon\/v\([^"]*\)".*/\1/')
[ -n "$VERSION" ] || die "Could not resolve latest daemon version from GitHub API"
echo "    version: ${VERSION}"

# Download
ARCHIVE="daemon_${VERSION}_linux_${GOARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/daemon/v${VERSION}/${ARCHIVE}"

step "Downloading ${ARCHIVE}..."
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM
curl -fsSL -o "${WORK_DIR}/${ARCHIVE}" "$URL"

# Install binaries
step "Installing binaries to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
mkdir -p "${WORK_DIR}/extract"
# Tarballs have a top-level directory (e.g. daemon_0.8.0_linux_amd64/); strip it.
tar -xzf "${WORK_DIR}/${ARCHIVE}" --strip-components=1 -C "${WORK_DIR}/extract"
install -m 0755 "${WORK_DIR}/extract/agent-receipts-daemon" "${INSTALL_DIR}/"
install -m 0755 "${WORK_DIR}/extract/agent-receipts"        "${INSTALL_DIR}/"

# Key init — skip if key already exists (idempotent on upgrades)
if [ -f "$KEY_FILE" ]; then
  echo "    signing key already present — skipping -init"
else
  step "Generating signing key..."
  "${INSTALL_DIR}/agent-receipts-daemon" -init
fi

# Install systemd user unit
step "Installing systemd user unit to ${UNIT_DIR}..."
mkdir -p "$UNIT_DIR"
cat > "${UNIT_DIR}/${UNIT_NAME}" << 'UNIT_EOF'
[Unit]
Description=Agent Receipts signing daemon
Documentation=https://github.com/agent-receipts/ar/tree/main/daemon

[Service]
Type=simple
# %h is the user's home directory; %t expands to $XDG_RUNTIME_DIR, ensuring the
# socket path is correct even when the service starts outside a PAM session.
ExecStartPre=/bin/sh -c 'test -f %h/.local/share/agent-receipts/signing.key || %h/.local/bin/agent-receipts-daemon -init'
ExecStart=%h/.local/bin/agent-receipts-daemon \
  -socket %t/agentreceipts/events.sock
Restart=on-failure
RestartSec=5s

# Ensure %t/agentreceipts/ exists before the socket bind.
RuntimeDirectory=agentreceipts
RuntimeDirectoryMode=0700

[Install]
WantedBy=default.target
UNIT_EOF

# Enable and start (or restart on upgrade).
# systemctl --user requires an active user session (XDG_RUNTIME_DIR set and
# /run/user/<uid>/systemd/private reachable). Ensure the variable is set so
# that installs over SSH without linger still attempt the enable step.
step "Enabling agent-receipts-daemon..."
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
if systemctl --user daemon-reload 2>/dev/null; then
  systemctl --user enable agent-receipts-daemon
  systemctl --user restart agent-receipts-daemon
  echo "    Service running."
else
  printf '    No active systemd user session detected.\n'
  printf '    After enabling linger (see below) and logging back in, run:\n'
  printf '      systemctl --user daemon-reload\n'
  printf '      systemctl --user enable --now agent-receipts-daemon\n'
fi

# Add XDG_RUNTIME_DIR export to ~/.bashrc so that SSH sessions without a full
# PAM login still have the variable set for user-service socket discovery.
if grep -qF 'XDG_RUNTIME_DIR' "$BASHRC" 2>/dev/null; then
  echo "    XDG_RUNTIME_DIR already in ${BASHRC} — skipping"
else
  step "Adding XDG_RUNTIME_DIR to ${BASHRC}..."
  printf '\n# Required for systemd user services in SSH sessions (added by agent-receipts install.sh)\n' >> "$BASHRC"
  # SC2016: single quotes are intentional — $(id -u) must expand at shell
  # startup when .bashrc is sourced, not here during install.
  # shellcheck disable=SC2016
  printf 'export XDG_RUNTIME_DIR=/run/user/$(id -u)\n' >> "$BASHRC"
fi

# Done
printf '\nagent-receipts-daemon v%s installed to %s.\n' "$VERSION" "$INSTALL_DIR"
printf '\n'
printf 'One root step required — enables the user session to persist across logouts:\n'
printf '\n'
printf '    sudo loginctl enable-linger %s\n' "$USER"
printf '\n'
printf 'Without linger, the daemon stops when you log out. After running the command\n'
printf 'above, log out and back in (or open a new SSH session) to activate it.\n'
printf '\n'
printf 'Note: MCP emitters running as system services need this in their unit file:\n'
printf '    Environment=XDG_RUNTIME_DIR=/run/user/<uid>\n'
printf 'See: https://github.com/agent-receipts/ar/tree/main/daemon/packaging/linux\n'
