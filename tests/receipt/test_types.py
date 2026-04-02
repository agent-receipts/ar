"""Tests for receipt types and constants."""

from agent_receipts.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
)
from tests.conftest import make_receipt, make_unsigned


class TestConstants:
    def test_context_has_two_entries(self) -> None:
        assert len(CONTEXT) == 2

    def test_context_starts_with_w3c(self) -> None:
        assert CONTEXT[0] == "https://www.w3.org/ns/credentials/v2"

    def test_context_includes_attest(self) -> None:
        assert CONTEXT[1] == "https://attest.sh/v1"

    def test_credential_type_has_two_entries(self) -> None:
        assert len(CREDENTIAL_TYPE) == 2

    def test_credential_type_includes_verifiable_credential(self) -> None:
        assert "VerifiableCredential" in CREDENTIAL_TYPE

    def test_credential_type_includes_agent_receipt(self) -> None:
        assert "AgentReceipt" in CREDENTIAL_TYPE

    def test_version(self) -> None:
        assert VERSION == "0.1.0"


class TestAgentReceipt:
    def test_make_receipt_creates_valid_receipt(self) -> None:
        receipt = make_receipt()
        assert receipt.id == "urn:receipt:test-1"
        assert receipt.proof.proofValue == "utest"

    def test_receipt_has_context(self) -> None:
        receipt = make_receipt()
        assert receipt.context == list(CONTEXT)

    def test_receipt_has_credential_type(self) -> None:
        receipt = make_receipt()
        assert receipt.type == list(CREDENTIAL_TYPE)


class TestUnsignedAgentReceipt:
    def test_make_unsigned_has_no_proof(self) -> None:
        unsigned = make_unsigned(1, None)
        assert not hasattr(unsigned, "proof") or "proof" not in unsigned.model_fields

    def test_unsigned_has_correct_id(self) -> None:
        unsigned = make_unsigned(1, None)
        assert unsigned.id == "urn:receipt:chain_test-1"

    def test_unsigned_has_correct_chain(self) -> None:
        unsigned = make_unsigned(1, None)
        assert unsigned.credentialSubject.chain.sequence == 1
        assert unsigned.credentialSubject.chain.previous_receipt_hash is None
