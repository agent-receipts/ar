"""Configuration resolution tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_receipts_hermes.config import (
    default_daemon_db_path,
    default_daemon_public_key_path,
    default_socket_path,
    resolve_config,
)


class TestSocketDefaults:
    def test_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTRECEIPTS_SOCKET", "/custom/sock")
        assert default_socket_path() == "/custom/sock"

    def test_linux_xdg_runtime_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
        assert default_socket_path() == "/run/user/1000/agentreceipts/events.sock"

    def test_linux_no_xdg_runtime_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        assert default_socket_path() == "/run/agentreceipts/events.sock"

    def test_macos_tmpdir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setenv("TMPDIR", "/var/folders/xy")
        assert default_socket_path() == "/var/folders/xy/agentreceipts/events.sock"


class TestDatabaseDefaults:
    def test_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTRECEIPTS_DB", "/tmp/x.db")
        assert default_daemon_db_path() == "/tmp/x.db"

    def test_xdg_data_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_DATA_HOME", "/data")
        assert default_daemon_db_path() == "/data/agent-receipts/receipts.db"

    def test_fallback_under_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: Path("/home/u")))
        assert (
            default_daemon_db_path()
            == "/home/u/.local/share/agent-receipts/receipts.db"
        )


class TestPublicKeyDefaults:
    def test_env_override_appends_pub(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTRECEIPTS_KEY", "/srv/k.key")
        assert default_daemon_public_key_path() == "/srv/k.key.pub"


class TestResolveConfig:
    def test_defaults_when_no_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTRECEIPTS_SOCKET", "/sock/x")
        monkeypatch.setenv("AGENTRECEIPTS_DB", "/db/x")
        monkeypatch.setenv("AGENTRECEIPTS_KEY", "/k/x.key")

        cfg = resolve_config(None)
        assert cfg.enabled is True
        assert cfg.socket_path == "/sock/x"
        assert cfg.daemon_db_path == "/db/x"
        assert cfg.daemon_public_key_path == "/k/x.key.pub"
        assert cfg.taxonomy_path is None
        assert cfg.channel == "hermes"
        assert cfg.deprecated_keys == ()

    def test_explicit_overrides_win(self) -> None:
        cfg = resolve_config(
            {
                "socketPath": "/explicit/sock",
                "daemonDbPath": "/explicit/db",
                "daemonPublicKeyPath": "/explicit/key.pub",
                "taxonomyPath": "/explicit/taxonomy.json",
                "channel": "custom-channel",
            }
        )
        assert cfg.socket_path == "/explicit/sock"
        assert cfg.daemon_db_path == "/explicit/db"
        assert cfg.daemon_public_key_path == "/explicit/key.pub"
        assert cfg.taxonomy_path == "/explicit/taxonomy.json"
        assert cfg.channel == "custom-channel"

    def test_enabled_false_disables_plugin(self) -> None:
        cfg = resolve_config({"enabled": False})
        assert cfg.enabled is False

    def test_deprecated_keys_surfaced(self) -> None:
        cfg = resolve_config(
            {
                "dbPath": "/x",
                "parameterDisclosure": True,
            }
        )
        assert "dbPath" in cfg.deprecated_keys
        assert "parameterDisclosure" in cfg.deprecated_keys

    def test_snake_case_aliases_accepted(self) -> None:
        cfg = resolve_config(
            {
                "socket_path": "/snake/sock",
                "daemon_db_path": "/snake/db",
                "daemon_public_key_path": "/snake/key.pub",
                "taxonomy_path": "/snake/tax.json",
            }
        )
        assert cfg.socket_path == "/snake/sock"
        assert cfg.daemon_db_path == "/snake/db"
        assert cfg.daemon_public_key_path == "/snake/key.pub"
        assert cfg.taxonomy_path == "/snake/tax.json"

    def test_tilde_expansion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", "/home/tester")
        cfg = resolve_config({"daemonDbPath": "~/db.sqlite"})
        # os.path.expanduser handles the leading tilde.
        assert cfg.daemon_db_path == os.path.expanduser("~/db.sqlite")
        assert "/home/tester/db.sqlite" == cfg.daemon_db_path
