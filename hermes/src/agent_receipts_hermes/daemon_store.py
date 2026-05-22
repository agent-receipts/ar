"""Read-only access to the daemon's SQLite receipt database.

The agent-facing ``ar_query_receipts`` and ``ar_verify_chain`` tools open
the daemon's database on every call so each invocation reflects the
freshest state. We wrap :class:`agent_receipts.store.ReceiptStore` with
thin helpers that close the connection deterministically and surface a
typed ``DaemonUnavailable`` error when the file is missing.
"""

from __future__ import annotations

import errno
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_receipts.store.store import ReceiptStore

if TYPE_CHECKING:
    from collections.abc import Generator

    from agent_receipts.receipt.types import AgentReceipt


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
    """Read the daemon's PEM public key, raising :class:`DaemonUnavailable`.

    Distinguishes permission-denied from missing-file so operators get a
    pointed hint when the daemon's key is mode 0600 and owned by another
    user — symptoms that would otherwise look identical to "daemon never
    started" from the agent's perspective.
    """
    try:
        return Path(path).read_text(encoding="utf-8")
    except PermissionError as exc:
        msg = (
            f"Cannot read daemon public key at {path}: permission denied. "
            "The daemon's signing key may be owned by another user; try "
            "running the agent as the daemon's user, or grant read access "
            "to the .pub file."
        )
        raise DaemonUnavailable(msg) from exc
    except OSError as exc:
        # ENOENT collapses into the generic message; anything else likely
        # warrants the daemon-not-running hint too. We branch defensively
        # in case PermissionError's hierarchy ever changes.
        if exc.errno == errno.EACCES:
            msg = f"Cannot read daemon public key at {path}: permission denied."
        else:
            msg = f"Cannot read daemon public key at {path}: {exc}"
        raise DaemonUnavailable(msg) from exc


def summarise_receipt(receipt: AgentReceipt) -> dict[str, Any]:
    """Flatten an :class:`agent_receipts.AgentReceipt` into a wire-friendly dict.

    Shared by the agent-facing ``ar_query_receipts`` tool and the
    Receipt Explorer CLI so the two surfaces always return the same shape.
    """
    sub = receipt.credentialSubject
    target = sub.action.target.resource if sub.action.target else None
    return {
        "id": receipt.id,
        "chain_id": sub.chain.chain_id,
        "action": sub.action.type,
        "risk": sub.action.risk_level,
        "target": target,
        "status": sub.outcome.status,
        "sequence": sub.chain.sequence,
        "timestamp": sub.action.timestamp,
    }


def broken_at_or_none(broken_at: int) -> int | None:
    """Normalise the SDK's ``-1`` sentinel into ``None`` for JSON payloads."""
    return broken_at if broken_at >= 0 else None
