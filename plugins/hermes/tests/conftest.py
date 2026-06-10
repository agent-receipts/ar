"""Shared pytest fixtures for the hermes plugin test suite."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.helpers import FakeCtx, FakeEmitter, FakeSocketServer


@pytest.fixture()
def fake_emitter() -> FakeEmitter:
    return FakeEmitter()


@pytest.fixture()
def fake_ctx() -> FakeCtx:
    return FakeCtx()


@pytest.fixture()
def tmp_socket(tmp_path: Path) -> Iterator[FakeSocketServer]:
    sock_path = str(tmp_path / "events.sock")
    server = FakeSocketServer(sock_path)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate tests from a developer's real daemon configuration."""
    for var in (
        "AGENTRECEIPTS_SOCKET",
        "AGENTRECEIPTS_DB",
        "AGENTRECEIPTS_KEY",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
    ):
        monkeypatch.delenv(var, raising=False)
