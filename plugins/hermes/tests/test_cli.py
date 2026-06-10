"""Smoke tests for the Receipt Explorer CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_receipts_hermes.cli import main
from tests.test_tools import _build_signed_chain


class TestReceiptsCommand:
    def test_table_output_includes_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        rc = main(["receipts", "--db", str(db)])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Total receipts: 3" in captured.out
        assert "system.command.execute" in captured.out

    def test_json_flag_emits_parseable_payload(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        rc = main(["receipts", "--db", str(db), "--json"])
        captured = capsys.readouterr()
        assert rc == 0
        payload = json.loads(captured.out)
        assert payload["stats"]["total"] == 3
        assert len(payload["receipts"]) == 3

    def test_missing_db_reports_friendly_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["receipts", "--db", str(tmp_path / "nope.db")])
        captured = capsys.readouterr()
        assert rc == 1
        assert "Is the agent-receipts daemon running?" in captured.err


class TestVerifyCommand:
    def test_valid_chain_returns_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        rc = main(["verify", "--db", str(db), "--key", str(key)])
        captured = capsys.readouterr()
        assert rc == 0
        assert "VALID" in captured.out


class TestExportCommand:
    def test_export_chain_emits_array(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        rc = main(
            [
                "export",
                "--db",
                str(db),
                "--chain",
                "chain-test",
            ]
        )
        captured = capsys.readouterr()
        assert rc == 0
        payload = json.loads(captured.out)
        assert isinstance(payload, list)
        assert len(payload) == 3

    def test_export_requires_chain_or_id(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["export", "--db", str(tmp_path / "x.db")])
        captured = capsys.readouterr()
        assert rc == 2
        assert "--chain" in captured.err
