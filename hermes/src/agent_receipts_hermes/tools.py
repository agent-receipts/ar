"""Agent-facing tools — ``ar_query_receipts`` and ``ar_verify_chain``.

Mirrors the openclaw plugin's tools API so the two implementations report
the same shape. Both tools open the daemon's database read-only on every
invocation so the agent always sees fresh state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_receipts.store.store import ReceiptQuery
from agent_receipts.store.verify import verify_stored_chain

from agent_receipts_hermes.daemon_store import (
    DaemonUnavailable,
    broken_at_or_none,
    open_daemon_store,
    read_public_key,
    summarise_receipt,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
_VALID_STATUSES = frozenset({"success", "failure", "pending"})

DEFAULT_QUERY_LIMIT = 20


@dataclass(frozen=True)
class ToolSpec:
    """Generic tool descriptor.

    Hermes' public tool-registration API is not documented in the public
    repo. We model the contract the way openclaw does — name, label,
    description, JSON-schema parameters, and an ``execute`` callable —
    then the plugin's ``register()`` adapts this shape to whatever
    method ``ctx`` exposes (``register_tool``, ``tool``, etc).
    """

    name: str
    label: str
    description: str
    parameters: dict[str, Any]
    execute: Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class ToolDeps:
    """Dependencies the tools need at registration time."""

    daemon_db_path: str
    daemon_public_key_path: str


def _parse_limit(value: Any) -> int:
    if not isinstance(value, (int, float)):
        return DEFAULT_QUERY_LIMIT
    as_int = int(value)
    if as_int < 0:
        return DEFAULT_QUERY_LIMIT
    return as_int


def query_receipts(deps: ToolDeps, params: dict[str, Any]) -> dict[str, Any]:
    """Execute the ``ar_query_receipts`` tool.

    Filters receipts by action type, risk level, status, and time window;
    returns newest-first with aggregate stats. Mirrors openclaw's response
    shape verbatim so dashboards and downstream tools can consume either.
    """
    raw_action = params.get("action_type")
    action_type = raw_action if isinstance(raw_action, str) else None
    raw_risk = params.get("risk_level")
    risk = raw_risk if raw_risk in _VALID_RISK_LEVELS else None
    raw_status = params.get("status")
    status = raw_status if raw_status in _VALID_STATUSES else None
    raw_after = params.get("timestamp_after")
    after = raw_after if isinstance(raw_after, str) else None
    raw_before = params.get("timestamp_before")
    before = raw_before if isinstance(raw_before, str) else None
    limit = _parse_limit(params.get("limit"))

    try:
        with open_daemon_store(deps.daemon_db_path) as store:
            # ReceiptQuery's ``after`` clause is ``timestamp > ?`` — already
            # strictly exclusive (sdk/py store.store.py). No post-filter needed.
            results = store.query(
                ReceiptQuery(
                    action_type=action_type,
                    risk_level=risk,
                    status=status,
                    after=after,
                    before=before,
                    limit=limit,
                    newest_first=True,
                )
            )
            stats = store.stats()
    except DaemonUnavailable as exc:
        return {
            "error": str(exc),
            "total_receipts": 0,
            "total_chains": 0,
            "by_risk": [],
            "by_status": [],
            "by_action": [],
            "results": [],
        }

    return {
        "total_receipts": stats.total,
        "total_chains": stats.chains,
        "by_risk": stats.by_risk,
        "by_status": stats.by_status,
        "by_action": stats.by_action,
        "results": [summarise_receipt(r) for r in results],
    }


def verify_chain_tool(deps: ToolDeps, params: dict[str, Any]) -> dict[str, Any]:
    """Execute the ``ar_verify_chain`` tool.

    Verifies Ed25519 signatures, hash links, and sequence numbering for a
    specific chain. When ``chain_id`` is omitted we pick the most recent
    chain so the typical "verify what I just did" call needs no arguments.
    """
    chain_id_raw = params.get("chain_id")
    requested_chain = (
        chain_id_raw if isinstance(chain_id_raw, str) and chain_id_raw else None
    )

    try:
        with open_daemon_store(deps.daemon_db_path) as store:
            chain_id = requested_chain
            if chain_id is None:
                recent = store.query(ReceiptQuery(limit=1, newest_first=True))
                if not recent:
                    return {
                        "chain_id": None,
                        "valid": False,
                        "length": 0,
                        "broken_at": None,
                        "receipts": [],
                        "message": "No receipts found in the daemon's database.",
                    }
                chain_id = recent[0].credentialSubject.chain.chain_id

            try:
                public_key = read_public_key(deps.daemon_public_key_path)
            except DaemonUnavailable as exc:
                return {
                    "chain_id": chain_id,
                    "valid": False,
                    "length": 0,
                    "broken_at": None,
                    "receipts": [],
                    "error": str(exc),
                }

            verification = verify_stored_chain(store, chain_id, public_key)
    except DaemonUnavailable as exc:
        return {
            "chain_id": requested_chain,
            "valid": False,
            "length": 0,
            "broken_at": None,
            "receipts": [],
            "error": str(exc),
        }

    return {
        "chain_id": chain_id,
        "valid": verification.valid,
        "length": verification.length,
        "broken_at": broken_at_or_none(verification.broken_at),
        "status": verification.status,
        "receipts": [
            {
                "index": r.index,
                "receipt_id": r.receipt_id,
                "signature_valid": r.signature_valid,
                "hash_link_valid": r.hash_link_valid,
                "sequence_valid": r.sequence_valid,
            }
            for r in verification.receipts
        ],
    }


def build_tools(deps: ToolDeps) -> list[ToolSpec]:
    """Build the two agent-facing tools, capturing ``deps`` in their closures."""
    query_params: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action_type": {
                "type": "string",
                "description": ('Filter by action type (e.g. "filesystem.file.read").'),
            },
            "risk_level": {
                "type": "string",
                "enum": sorted(_VALID_RISK_LEVELS),
                "description": "Filter by risk level.",
            },
            "status": {
                "type": "string",
                "enum": sorted(_VALID_STATUSES),
                "description": "Filter by outcome status.",
            },
            "timestamp_after": {
                "type": "string",
                "description": (
                    "ISO-8601 timestamp; receipts strictly after this point."
                ),
            },
            "timestamp_before": {
                "type": "string",
                "description": (
                    "ISO-8601 timestamp; receipts at or before this point."
                ),
            },
            "limit": {
                "type": "integer",
                "minimum": 0,
                "description": (
                    "Maximum number of receipts to return "
                    f"(default: {DEFAULT_QUERY_LIMIT})."
                ),
            },
        },
        "additionalProperties": False,
    }

    verify_params: dict[str, Any] = {
        "type": "object",
        "properties": {
            "chain_id": {
                "type": "string",
                "description": (
                    "Chain ID to verify; the most recent chain is used if omitted."
                ),
            }
        },
        "additionalProperties": False,
    }

    return [
        ToolSpec(
            name="ar_query_receipts",
            label="Query Agent Receipts",
            description=(
                "Search the cryptographic audit trail in the daemon's receipt "
                "database. Returns newest-first across all sessions, with "
                "aggregate stats. Use timestamp_after to poll for new actions "
                "since your last check."
            ),
            parameters=query_params,
            execute=lambda p, d=deps: query_receipts(d, p),
        ),
        ToolSpec(
            name="ar_verify_chain",
            label="Verify Agent Receipts Chain",
            description=(
                "Cryptographically verify the integrity of the daemon's "
                "receipt chain. Checks Ed25519 signatures, hash links, and "
                "sequence numbering. Auto-selects the most recent chain when "
                "chain_id is omitted."
            ),
            parameters=verify_params,
            execute=lambda p, d=deps: verify_chain_tool(d, p),
        ),
    ]
