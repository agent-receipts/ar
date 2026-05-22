"""Receipt Explorer CLI for the hermes-agent Agent Receipts plugin.

Query and verify the daemon's SQLite receipt database outside of an agent
session — useful for auditing and debugging. Mirrors the openclaw CLI's
subcommands so operators can use either with the same muscle memory.

Usage:
    agent-receipts-hermes receipts [options]
    agent-receipts-hermes verify   [options]
    agent-receipts-hermes export   [options]
    agent-receipts-hermes --help
    agent-receipts-hermes --version
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_receipts.store.store import ReceiptQuery
from agent_receipts.store.verify import verify_stored_chain

from agent_receipts_hermes._version import VERSION
from agent_receipts_hermes.config import (
    default_daemon_db_path,
    default_daemon_public_key_path,
)
from agent_receipts_hermes.daemon_store import (
    DaemonUnavailable,
    broken_at_or_none,
    open_daemon_store,
    read_public_key,
    summarise_receipt,
)

_VALID_RISK_LEVELS = ("low", "medium", "high", "critical")
_VALID_STATUSES = ("success", "failure", "pending")
_VALID_FORMATS = ("receipt", "presentation")
_DEFAULT_LIMIT = 20


@dataclass(frozen=True)
class _Args:
    command: str
    risk: str | None
    action: str | None
    status: str | None
    limit: int
    db: str
    key: str
    chain: str | None
    receipt_id: str | None
    out_format: str
    as_json: bool


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-receipts-hermes",
        description="Receipt Explorer for the hermes-agent plugin.",
    )
    parser.add_argument(
        "--version", action="version", version=f"agent-receipts-hermes v{VERSION}"
    )

    sub = parser.add_subparsers(dest="command", required=False)

    common_db = argparse.ArgumentParser(add_help=False)
    common_db.add_argument(
        "--db",
        default=default_daemon_db_path(),
        help=(
            "Path to the daemon's SQLite database (defaults to AGENTRECEIPTS_DB / XDG)."
        ),
    )

    common_key = argparse.ArgumentParser(add_help=False)
    common_key.add_argument(
        "--key",
        default=default_daemon_public_key_path(),
        help="Path to the daemon's PEM public key (used for signature checks).",
    )

    receipts = sub.add_parser(
        "receipts", parents=[common_db], help="Query stored receipts."
    )
    receipts.add_argument("--risk", choices=_VALID_RISK_LEVELS)
    receipts.add_argument("--action", help="Filter by action type.")
    receipts.add_argument("--status", choices=_VALID_STATUSES)
    receipts.add_argument(
        "--limit", type=int, default=_DEFAULT_LIMIT, help="Maximum rows (default 20)."
    )
    receipts.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a table.",
    )

    verify = sub.add_parser(
        "verify",
        parents=[common_db, common_key],
        help="Verify a chain's signatures and hash linkage.",
    )
    verify.add_argument(
        "--chain",
        help="Chain ID to verify. All chains in the DB are verified when omitted.",
    )
    verify.add_argument("--json", action="store_true")

    export = sub.add_parser(
        "export",
        parents=[common_db],
        help="Export receipts as JSON-LD (single, chain, or VP).",
    )
    export.add_argument("--chain", help="Export every receipt in this chain.")
    export.add_argument(
        "--id",
        dest="receipt_id",
        help="Export a single receipt by ID.",
    )
    export.add_argument(
        "--format",
        choices=_VALID_FORMATS,
        default="receipt",
        help="Output shape: raw receipt(s) or W3C Verifiable Presentation envelope.",
    )

    return parser


def _parse_args(argv: list[str]) -> _Args:
    parser = _build_parser()
    ns = parser.parse_args(argv)

    if ns.command is None:
        parser.print_help()
        sys.exit(0)

    return _Args(
        command=str(ns.command),
        risk=getattr(ns, "risk", None),
        action=getattr(ns, "action", None),
        status=getattr(ns, "status", None),
        limit=int(getattr(ns, "limit", _DEFAULT_LIMIT)),
        db=str(ns.db),
        key=str(getattr(ns, "key", default_daemon_public_key_path())),
        chain=getattr(ns, "chain", None),
        receipt_id=getattr(ns, "receipt_id", None),
        out_format=str(getattr(ns, "format", "receipt")),
        as_json=bool(getattr(ns, "json", False)),
    )


def _expand(path: str) -> str:
    return str(Path(path).expanduser())


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)] + "…"


def _format_table(receipts: list[Any], stats: Any) -> str:
    lines: list[str] = [
        f"Total receipts: {stats.total}  |  Chains: {stats.chains}",
    ]
    if stats.by_risk:
        risk_parts = ", ".join(
            f"{r['risk_level']}: {r['count']}" for r in stats.by_risk
        )
        lines.append("Risk: " + risk_parts)
    if stats.by_status:
        lines.append(
            "Status: "
            + ", ".join(f"{s['status']}: {s['count']}" for s in stats.by_status)
        )
    lines.append("")

    if not receipts:
        lines.append("No receipts found.")
        return "\n".join(lines)

    header = (
        f"{'#':>5}  {'ACTION':<30}  {'RISK':<8}  {'STATUS':<8}  "
        f"{'TARGET':<20}  {'TIMESTAMP':<20}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for r in receipts:
        sub = r.credentialSubject
        target = sub.action.target.resource if sub.action.target else "-"
        lines.append(
            f"{sub.chain.sequence:>5}  "
            f"{_truncate(sub.action.type, 30):<30}  "
            f"{sub.action.risk_level:<8}  "
            f"{sub.outcome.status:<8}  "
            f"{_truncate(target, 20):<20}  "
            f"{sub.action.timestamp:<20}"
        )
    lines.append("")
    lines.append(f"Showing {len(receipts)} of {stats.total} receipts.")
    return "\n".join(lines)


def _run_receipts(args: _Args) -> int:
    db_path = _expand(args.db)
    try:
        with open_daemon_store(db_path) as store:
            results = store.query(
                ReceiptQuery(
                    risk_level=args.risk,
                    action_type=args.action,
                    status=args.status,
                    limit=args.limit,
                    newest_first=True,
                )
            )
            stats = store.stats()
    except DaemonUnavailable as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    if args.as_json:
        payload = {
            "stats": {
                "total": stats.total,
                "chains": stats.chains,
                "by_risk": stats.by_risk,
                "by_status": stats.by_status,
                "by_action": stats.by_action,
            },
            "receipts": [summarise_receipt(r) for r in results],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(_format_table(results, stats) + "\n")
    return 0


def _run_verify(args: _Args) -> int:
    db_path = _expand(args.db)
    try:
        public_key = read_public_key(_expand(args.key))
    except DaemonUnavailable as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    try:
        with open_daemon_store(db_path) as store:
            if args.chain:
                verification = verify_stored_chain(store, args.chain, public_key)
                _print_verify(args, args.chain, verification)
                return 0 if verification.valid else 1

            all_receipts = store.query(ReceiptQuery())
            if not all_receipts:
                msg = "No receipts found in the daemon's database."
                if args.as_json:
                    sys.stdout.write(json.dumps({"chains": []}, indent=2) + "\n")
                else:
                    sys.stdout.write(msg + "\n")
                return 0

            chain_ids: list[str] = []
            seen: set[str] = set()
            for r in all_receipts:
                cid = r.credentialSubject.chain.chain_id
                if cid not in seen:
                    seen.add(cid)
                    chain_ids.append(cid)

            ok = True
            results: list[dict[str, Any]] = []
            for cid in chain_ids:
                v = verify_stored_chain(store, cid, public_key)
                ok = ok and v.valid
                results.append(
                    {
                        "chain_id": cid,
                        "valid": v.valid,
                        "length": v.length,
                        "broken_at": broken_at_or_none(v.broken_at),
                    }
                )

            if args.as_json:
                sys.stdout.write(json.dumps({"chains": results}, indent=2) + "\n")
            else:
                for r in results:
                    status = "VALID" if r["valid"] else f"BROKEN at {r['broken_at']}"
                    sys.stdout.write(
                        f"{r['chain_id']}: {status} ({r['length']} receipts)\n"
                    )
            return 0 if ok else 1
    except DaemonUnavailable as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1


def _print_verify(args: _Args, chain_id: str, verification: Any) -> None:
    if args.as_json:
        payload = {
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
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return

    if verification.valid:
        sys.stdout.write(
            f'Chain "{chain_id}" is valid: {verification.length} receipts, '
            "all signatures and hash links verified.\n"
        )
        return

    sys.stdout.write(
        f'Chain "{chain_id}" is BROKEN at position {verification.broken_at}.\n'
    )
    for r in verification.receipts:
        if r.signature_valid and r.hash_link_valid and r.sequence_valid:
            continue
        issues: list[str] = []
        if not r.signature_valid:
            issues.append("signature")
        if not r.hash_link_valid:
            issues.append("hash link")
        if not r.sequence_valid:
            issues.append("sequence")
        sys.stdout.write(f"  [{r.index}] {r.receipt_id}: invalid {', '.join(issues)}\n")


def _run_export(args: _Args) -> int:
    if args.chain and args.receipt_id:
        sys.stderr.write("Error: use --chain OR --id, not both.\n")
        return 2
    if not args.chain and not args.receipt_id:
        sys.stderr.write("Error: export requires --chain <id> or --id <receipt-id>.\n")
        return 2

    db_path = _expand(args.db)
    try:
        with open_daemon_store(db_path) as store:
            if args.receipt_id:
                receipt = store.get_by_id(args.receipt_id)
                if receipt is None:
                    sys.stderr.write(f'Error: receipt not found: "{args.receipt_id}"\n')
                    return 1
                payload: Any = (
                    _wrap_presentation([receipt])
                    if args.out_format == "presentation"
                    else _receipt_to_jsonable(receipt)
                )
            else:
                assert args.chain is not None
                receipts = store.get_chain(args.chain)
                if not receipts:
                    sys.stderr.write(
                        f'Error: no receipts found for chain: "{args.chain}"\n'
                    )
                    return 1
                payload = (
                    _wrap_presentation(receipts)
                    if args.out_format == "presentation"
                    else [_receipt_to_jsonable(r) for r in receipts]
                )
    except DaemonUnavailable as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
    return 0


def _receipt_to_jsonable(receipt: Any) -> dict[str, Any]:
    return receipt.model_dump(by_alias=True, exclude_none=True)


def _wrap_presentation(receipts: list[Any]) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": "VerifiablePresentation",
        "verifiableCredential": [_receipt_to_jsonable(r) for r in receipts],
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point used by ``agent-receipts-hermes`` console script."""
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])
    if args.command == "receipts":
        return _run_receipts(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "export":
        return _run_export(args)
    sys.stderr.write(f"Error: unknown command {args.command!r}\n")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
