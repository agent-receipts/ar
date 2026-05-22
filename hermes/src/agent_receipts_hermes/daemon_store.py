"""Read-only access to the daemon's SQLite receipt database.

The agent-facing ``ar_query_receipts`` and ``ar_verify_chain`` tools open
the daemon's database on every call so each invocation reflects the
freshest state. We wrap :class:`agent_receipts.store.ReceiptStore` with
thin helpers that close the connection deterministically and surface a
typed ``DaemonUnavailable`` error when the file is missing.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from agent_receipts.store.store import ReceiptStore

if TYPE_CHECKING:
    from collections.abc import Generator


class DaemonUnavailable(RuntimeError):
    """Raised when the daemon's SQLite database cannot be opened."""


@contextmanager
def open_daemon_store(db_path: str) -> Generator[ReceiptStore, None, None]:
    """Open the daemon's receipt database read-only, closing on exit.

    Raises :class:`DaemonUnavailable` when the file is missing (the usual
    "daemon never started" symptom) so callers can render a friendly error
    instead of leaking ``sqlite3`` exceptions out to the agent.
    """
    if not Path(db_path).exists():
        msg = (
            f"Cannot open daemon database at {db_path}. "
            "Is the agent-receipts daemon running?"
        )
        raise DaemonUnavailable(msg)

    try:
        store = ReceiptStore(db_path)
    except sqlite3.Error as exc:
        msg = f"Failed to open daemon database at {db_path}: {exc}"
        raise DaemonUnavailable(msg) from exc

    try:
        yield store
    finally:
        store.close()


def read_public_key(path: str) -> str:
    """Read the daemon's PEM public key, raising :class:`DaemonUnavailable`."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Cannot read daemon public key at {path}: {exc}"
        raise DaemonUnavailable(msg) from exc
