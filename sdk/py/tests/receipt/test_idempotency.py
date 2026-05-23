"""Tests for action.idempotency_key (spec §7.3.6, ADR-0019 §S5)."""

from __future__ import annotations

from agent_receipts.receipt.chain import verify_chain
from agent_receipts.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from agent_receipts.receipt.hash import canonicalize, hash_receipt
from agent_receipts.receipt.signing import sign_receipt
from agent_receipts.receipt.types import (
    AgentReceipt,
    Chain,
    Issuer,
    Outcome,
    Principal,
)
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY


def _build_chain_with_keys(
    idempotency_keys: list[str | None], private_key: str
) -> list[AgentReceipt]:
    """Build a signed, hash-linked chain whose i-th receipt carries
    idempotency_keys[i] on action.idempotency_key (None = omitted)."""
    chain: list[AgentReceipt] = []
    previous_hash: str | None = None
    for i, key in enumerate(idempotency_keys):
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(
                    type="filesystem.file.read",
                    risk_level="low",
                    idempotency_key=key,
                ),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=i + 1,
                    previous_receipt_hash=previous_hash,
                    chain_id="chain_test",
                ),
            )
        )
        signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
        chain.append(signed)
        previous_hash = hash_receipt(signed)
    return chain


class TestIdempotencyKey:
    def test_create_stamps_idempotency_key(self) -> None:
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:alice"),
                action=ActionInput(
                    type="filesystem.file.read",
                    risk_level="low",
                    idempotency_key="req-1",
                ),
                outcome=Outcome(status="success"),
                chain=Chain(sequence=1, previous_receipt_hash=None, chain_id="c"),
            )
        )
        assert unsigned.credentialSubject.action.idempotency_key == "req-1"

    def test_omitted_when_unset(self) -> None:
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:alice"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(sequence=1, previous_receipt_hash=None, chain_id="c"),
            )
        )
        wire = unsigned.model_dump(by_alias=True, exclude_none=True)
        assert "idempotency_key" not in canonicalize(wire)

    def test_duplicate_surfaces_as_warning_not_failure(self) -> None:
        # Receipts 0 and 2 share "req-A"; receipt 1 has a distinct key.
        chain = _build_chain_with_keys(["req-A", "req-B", "req-A"], TEST_PRIVATE_KEY)
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert len(result.warnings) == 1
        warning = result.warnings[0]
        assert "req-A" in warning
        assert "0" in warning
        assert "2" in warning

    def test_no_warning_for_distinct_or_absent_keys(self) -> None:
        for keys in (
            ["req-1", "req-2", "req-3"],
            [None, None, None],
            ["req-1", None, "req-2"],
        ):
            chain = _build_chain_with_keys(keys, TEST_PRIVATE_KEY)
            result = verify_chain(chain, TEST_PUBLIC_KEY)
            assert result.valid is True
            assert result.warnings == []
