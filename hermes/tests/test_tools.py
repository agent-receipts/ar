"""Tests for the agent-facing ``ar_query_receipts`` / ``ar_verify_chain`` tools."""

from __future__ import annotations

from pathlib import Path

from agent_receipts import (
    generate_key_pair,
    hash_receipt,
    open_store,
    sign_receipt,
)
from agent_receipts.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from agent_receipts.receipt.types import (
    ActionTarget,
    Chain,
    Issuer,
    Outcome,
    Principal,
)

from agent_receipts_hermes.tools import (
    ToolDeps,
    build_tools,
    query_receipts,
    verify_chain_tool,
)


def _build_signed_chain(
    db_path: Path,
    public_key_path: Path,
    *,
    chain_id: str = "chain-test",
    receipts: int = 3,
) -> str:
    """Create a small signed receipt chain on disk and return the PEM pubkey.

    Uses the SDK's test-key generator — never a real production key.
    """
    keypair = generate_key_pair()
    store = open_store(str(db_path))
    previous_hash: str | None = None
    actions = [
        ("read_file", "filesystem.file.read", "low", "/etc/hosts"),
        ("bash", "system.command.execute", "high", "echo hi"),
        ("web_fetch", "system.browser.navigate", "low", "https://example.com"),
    ][:receipts]

    for i, (_tool, action_type, risk, target) in enumerate(actions, start=1):
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:test:hermes"),
                principal=Principal(id="did:session:test"),
                action=ActionInput(
                    type=action_type,
                    risk_level=risk,
                    target=ActionTarget(system="hermes", resource=target),
                ),
                outcome=Outcome(status="success"),
                chain=Chain(
                    chain_id=chain_id,
                    sequence=i,
                    previous_receipt_hash=previous_hash,
                ),
                action_timestamp=f"2026-05-22T00:00:{i:02d}.000Z",
            )
        )
        signed = sign_receipt(
            unsigned,
            keypair.private_key,
            verification_method="did:test:hermes#key-1",
        )
        receipt_hash = hash_receipt(signed)
        store.insert(signed, receipt_hash)
        previous_hash = receipt_hash

    store.close()
    public_key_path.write_text(keypair.public_key, encoding="utf-8")
    return keypair.public_key


class TestQueryReceipts:
    def test_returns_summary_and_results(self, tmp_path: Path) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = query_receipts(deps, {})

        assert "error" not in result
        assert result["total_receipts"] == 3
        assert result["total_chains"] == 1
        assert len(result["results"]) == 3
        # Newest-first: the third action appears first.
        assert result["results"][0]["action"] == "system.browser.navigate"

    def test_filters_by_risk(self, tmp_path: Path) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = query_receipts(deps, {"risk_level": "high"})

        actions = [r["action"] for r in result["results"]]
        assert actions == ["system.command.execute"]

    def test_invalid_risk_is_ignored(self, tmp_path: Path) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = query_receipts(deps, {"risk_level": "definitely-not-a-level"})
        assert len(result["results"]) == 3

    def test_missing_db_returns_friendly_error(self, tmp_path: Path) -> None:
        deps = ToolDeps(
            daemon_db_path=str(tmp_path / "nope.db"),
            daemon_public_key_path=str(tmp_path / "nope.pub"),
        )
        result = query_receipts(deps, {})
        assert "error" in result
        assert result["total_receipts"] == 0


class TestVerifyChain:
    def test_valid_chain_passes(self, tmp_path: Path) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key)

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = verify_chain_tool(deps, {"chain_id": "chain-test"})
        assert result["valid"] is True
        assert result["length"] == 3
        assert result["broken_at"] is None
        assert len(result["receipts"]) == 3
        assert all(r["signature_valid"] for r in result["receipts"])

    def test_auto_picks_recent_chain_when_id_omitted(self, tmp_path: Path) -> None:
        db = tmp_path / "receipts.db"
        key = tmp_path / "signing.key.pub"
        _build_signed_chain(db, key, chain_id="chain-auto")

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = verify_chain_tool(deps, {})
        assert result["chain_id"] == "chain-auto"
        assert result["valid"] is True

    def test_missing_db_returns_friendly_error(self, tmp_path: Path) -> None:
        deps = ToolDeps(
            daemon_db_path=str(tmp_path / "nope.db"),
            daemon_public_key_path=str(tmp_path / "nope.pub"),
        )
        result = verify_chain_tool(deps, {"chain_id": "x"})
        assert result["valid"] is False
        assert "error" in result

    def test_empty_db_reports_no_receipts(self, tmp_path: Path) -> None:
        db = tmp_path / "empty.db"
        # Open the store once to create the schema, then close.
        open_store(str(db)).close()
        key = tmp_path / "signing.key.pub"
        key.write_text("placeholder", encoding="utf-8")

        deps = ToolDeps(daemon_db_path=str(db), daemon_public_key_path=str(key))
        result = verify_chain_tool(deps, {})
        assert result["valid"] is False
        assert result["length"] == 0
        assert "message" in result


class TestBuildTools:
    def test_returns_query_and_verify(self, tmp_path: Path) -> None:
        deps = ToolDeps(
            daemon_db_path=str(tmp_path / "db"),
            daemon_public_key_path=str(tmp_path / "k.pub"),
        )
        specs = build_tools(deps)
        names = {t.name for t in specs}
        assert names == {"ar_query_receipts", "ar_verify_chain"}
        # Parameters are JSON Schema objects so hermes can validate args.
        for spec in specs:
            assert spec.parameters["type"] == "object"

    def test_execute_callable_invokes_underlying_function(self, tmp_path: Path) -> None:
        deps = ToolDeps(
            daemon_db_path=str(tmp_path / "absent.db"),
            daemon_public_key_path=str(tmp_path / "absent.pub"),
        )
        specs = build_tools(deps)
        query = next(t for t in specs if t.name == "ar_query_receipts")
        result = query.execute({})
        assert "error" in result  # DB doesn't exist
