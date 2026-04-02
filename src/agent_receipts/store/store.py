"""SQLite-backed receipt store."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_receipts.receipt.types import AgentReceipt

DEFAULT_QUERY_LIMIT = 10_000

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  chain_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  status TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  principal_id TEXT,
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL,
  previous_receipt_hash TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_receipts_action ON receipts(action_type);
CREATE INDEX IF NOT EXISTS idx_receipts_risk ON receipts(risk_level);
CREATE INDEX IF NOT EXISTS idx_receipts_status ON receipts(status);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
"""


@dataclass
class ReceiptQuery:
    """Filter parameters for querying stored receipts."""

    chain_id: str | None = None
    action_type: str | None = None
    risk_level: str | None = None
    status: str | None = None
    after: str | None = None
    before: str | None = None
    limit: int | None = None


@dataclass
class StoreStats:
    """Aggregate statistics about stored receipts."""

    total: int
    chains: int
    by_risk: list[dict[str, str | int]]
    by_status: list[dict[str, str | int]]
    by_action: list[dict[str, str | int]]


class ReceiptStore:
    """SQLite-backed store for Agent Receipts."""

    def __init__(self, db_path: str) -> None:
        """Open the database and ensure the schema exists."""
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def insert(self, receipt: AgentReceipt, receipt_hash: str) -> None:
        """Insert a signed receipt into the store."""
        subject = receipt.credentialSubject
        chain = subject.chain
        action = subject.action
        outcome = subject.outcome
        principal = subject.principal

        receipt_json = json.dumps(receipt.model_dump(by_alias=True), default=str)

        self._conn.execute(
            """
            INSERT INTO receipts
                (id, chain_id, sequence, action_type, risk_level, status,
                 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
                 previous_receipt_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.id,
                chain.chain_id,
                chain.sequence,
                action.type,
                action.risk_level,
                outcome.status,
                action.timestamp,
                receipt.issuer.id,
                principal.id if principal else None,
                receipt_json,
                receipt_hash,
                chain.previous_receipt_hash,
            ),
        )
        self._conn.commit()

    def get_by_id(self, receipt_id: str) -> AgentReceipt | None:
        """Retrieve a single receipt by its ID, or ``None`` if not found."""
        row = self._conn.execute(
            "SELECT receipt_json FROM receipts WHERE id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            return None
        return _parse_receipt(row["receipt_json"])

    def get_chain(self, chain_id: str) -> list[AgentReceipt]:
        """Return all receipts in a chain, ordered by sequence number."""
        rows = self._conn.execute(
            "SELECT receipt_json FROM receipts WHERE chain_id = ? ORDER BY sequence",
            (chain_id,),
        ).fetchall()
        return [_parse_receipt(r["receipt_json"]) for r in rows]

    def query(self, filters: ReceiptQuery) -> list[AgentReceipt]:
        """Query receipts with optional filters."""
        clauses: list[str] = []
        params: list[str | int] = []

        if filters.chain_id is not None:
            clauses.append("chain_id = ?")
            params.append(filters.chain_id)
        if filters.action_type is not None:
            clauses.append("action_type = ?")
            params.append(filters.action_type)
        if filters.risk_level is not None:
            clauses.append("risk_level = ?")
            params.append(filters.risk_level)
        if filters.status is not None:
            clauses.append("status = ?")
            params.append(filters.status)
        if filters.after is not None:
            clauses.append("timestamp > ?")
            params.append(filters.after)
        if filters.before is not None:
            clauses.append("timestamp < ?")
            params.append(filters.before)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = filters.limit if filters.limit is not None else DEFAULT_QUERY_LIMIT
        params.append(limit)

        sql = f"SELECT receipt_json FROM receipts{where} ORDER BY timestamp LIMIT ?"  # noqa: S608
        rows = self._conn.execute(sql, params).fetchall()
        return [_parse_receipt(r["receipt_json"]) for r in rows]

    def stats(self) -> StoreStats:
        """Return aggregate statistics about the store."""
        total = self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        chains = self._conn.execute(
            "SELECT COUNT(DISTINCT chain_id) FROM receipts"
        ).fetchone()[0]
        by_risk = _group_rows(
            self._conn.execute(
                "SELECT risk_level, COUNT(*) as count FROM receipts GROUP BY risk_level"
            ).fetchall(),
            "risk_level",
        )
        by_status = _group_rows(
            self._conn.execute(
                "SELECT status, COUNT(*) as count FROM receipts GROUP BY status"
            ).fetchall(),
            "status",
        )
        by_action = _group_rows(
            self._conn.execute(
                "SELECT action_type, COUNT(*) as count "
                "FROM receipts GROUP BY action_type"
            ).fetchall(),
            "action_type",
        )
        return StoreStats(
            total=total,
            chains=chains,
            by_risk=by_risk,
            by_status=by_status,
            by_action=by_action,
        )

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()


def open_store(db_path: str) -> ReceiptStore:
    """Factory function to create a ReceiptStore."""
    return ReceiptStore(db_path)


def _parse_receipt(json_str: str) -> AgentReceipt:
    """Deserialize a receipt from its stored JSON."""
    from agent_receipts.receipt.types import AgentReceipt

    return AgentReceipt.model_validate(json.loads(json_str))


def _group_rows(
    rows: list[sqlite3.Row],
    key_name: str,
) -> list[dict[str, str | int]]:
    result: list[dict[str, str | int]] = []
    for row in rows:
        result.append({key_name: str(row[key_name]), "count": int(row["count"])})
    return result
