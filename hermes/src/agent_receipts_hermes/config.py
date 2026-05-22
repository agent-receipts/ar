"""Configuration resolution for the hermes-agent Agent Receipts plugin.

Defaults mirror the openclaw plugin and the daemon's own resolution so
both sides agree on the same socket / database / public key paths.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _expand(path: str) -> str:
    """Expand ``~`` and environment variables in ``path``.

    Trusts the caller to validate the result; this is only string expansion.
    """
    return os.path.expanduser(os.path.expandvars(path))


def default_socket_path() -> str:
    """Return the daemon's default Unix socket path.

    Mirrors :func:`agent_receipts.emitter.default_socket_path` exactly so
    explicit overrides resolve consistently across plugin and SDK.
    """
    env = os.environ.get("AGENTRECEIPTS_SOCKET", "")
    if env:
        return env

    system = platform.system()
    if system == "Darwin":
        base = os.environ.get("TMPDIR") or "/tmp"  # noqa: S108
        return os.path.join(base, "agentreceipts", "events.sock")
    if system == "Linux":
        xdg = os.environ.get("XDG_RUNTIME_DIR", "")
        if xdg:
            return os.path.join(xdg, "agentreceipts", "events.sock")
        return "/run/agentreceipts/events.sock"
    return ""


def default_daemon_db_path() -> str:
    """Return the daemon's default SQLite database path.

    Resolution order:
      1. ``AGENTRECEIPTS_DB`` env var.
      2. ``$XDG_DATA_HOME/agent-receipts/receipts.db``.
      3. ``~/.local/share/agent-receipts/receipts.db``.
    """
    env_path = os.environ.get("AGENTRECEIPTS_DB", "")
    if env_path:
        return env_path

    xdg = os.environ.get("XDG_DATA_HOME", "")
    base = xdg if xdg else os.path.join(str(Path.home()), ".local", "share")
    return os.path.join(base, "agent-receipts", "receipts.db")


def default_daemon_public_key_path() -> str:
    """Return the daemon's default Ed25519 public key path.

    Resolution order:
      1. ``AGENTRECEIPTS_KEY`` env var + ``.pub`` suffix.
      2. ``$XDG_DATA_HOME/agent-receipts/signing.key.pub``.
      3. ``~/.local/share/agent-receipts/signing.key.pub``.
    """
    env_key = os.environ.get("AGENTRECEIPTS_KEY", "")
    if env_key:
        return f"{env_key}.pub"

    xdg = os.environ.get("XDG_DATA_HOME", "")
    base = xdg if xdg else os.path.join(str(Path.home()), ".local", "share")
    return os.path.join(base, "agent-receipts", "signing.key.pub")


@dataclass(frozen=True)
class PluginConfig:
    """Resolved plugin configuration."""

    enabled: bool = True
    socket_path: str = ""
    daemon_db_path: str = ""
    daemon_public_key_path: str = ""
    taxonomy_path: str | None = None
    channel: str = "hermes"
    deprecated_keys: tuple[str, ...] = field(default_factory=tuple)


_DEPRECATED_KEYS = ("dbPath", "keyPath", "daemonForwarding", "parameterDisclosure")


def resolve_config(raw: dict[str, Any] | None) -> PluginConfig:
    """Resolve plugin config from a raw dict (typically from ``plugin.yaml``).

    Unknown keys are accepted silently so future hermes config additions
    do not break the plugin; legacy openclaw-style keys are surfaced via
    ``PluginConfig.deprecated_keys`` so the caller can log a warning.
    """
    cfg_dict: dict[str, Any] = raw or {}

    enabled_raw: object = cfg_dict.get("enabled", True)
    enabled = bool(enabled_raw) if enabled_raw is not None else True

    socket_path_raw: object = cfg_dict.get("socketPath") or cfg_dict.get("socket_path")
    socket_path = (
        _expand(socket_path_raw)
        if isinstance(socket_path_raw, str) and socket_path_raw
        else default_socket_path()
    )

    db_path_raw: object = cfg_dict.get("daemonDbPath") or cfg_dict.get("daemon_db_path")
    db_path = (
        _expand(db_path_raw)
        if isinstance(db_path_raw, str) and db_path_raw
        else default_daemon_db_path()
    )

    key_path_raw: object = cfg_dict.get("daemonPublicKeyPath") or cfg_dict.get(
        "daemon_public_key_path"
    )
    key_path = (
        _expand(key_path_raw)
        if isinstance(key_path_raw, str) and key_path_raw
        else default_daemon_public_key_path()
    )

    taxonomy_raw: object = cfg_dict.get("taxonomyPath") or cfg_dict.get("taxonomy_path")
    taxonomy_path = (
        _expand(taxonomy_raw)
        if isinstance(taxonomy_raw, str) and taxonomy_raw
        else None
    )

    channel_raw: object = cfg_dict.get("channel", "hermes")
    channel = channel_raw if isinstance(channel_raw, str) and channel_raw else "hermes"

    deprecated: tuple[str, ...] = tuple(k for k in _DEPRECATED_KEYS if k in cfg_dict)

    return PluginConfig(
        enabled=enabled,
        socket_path=socket_path,
        daemon_db_path=db_path,
        daemon_public_key_path=key_path,
        taxonomy_path=taxonomy_path,
        channel=channel,
        deprecated_keys=deprecated,
    )
