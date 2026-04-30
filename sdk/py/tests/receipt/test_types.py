"""Tests for receipt types and constants."""

from agent_receipts.receipt.hash import hash_receipt
from agent_receipts.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    AgentReceipt,
)
from tests.conftest import make_receipt, make_unsigned


class TestConstants:
    def test_context_has_two_entries(self) -> None:
        assert len(CONTEXT) == 2

    def test_context_starts_with_w3c(self) -> None:
        assert CONTEXT[0] == "https://www.w3.org/ns/credentials/v2"

    def test_context_includes_attest(self) -> None:
        assert CONTEXT[1] == "https://agentreceipts.ai/context/v1"

    def test_credential_type_has_two_entries(self) -> None:
        assert len(CREDENTIAL_TYPE) == 2

    def test_credential_type_includes_verifiable_credential(self) -> None:
        assert "VerifiableCredential" in CREDENTIAL_TYPE

    def test_credential_type_includes_agent_receipt(self) -> None:
        assert "AgentReceipt" in CREDENTIAL_TYPE

    def test_version(self) -> None:
        assert VERSION == "0.2.0"


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


class TestParametersDisclosure:
    """Round-trip tests for the optional Action.parameters_disclosure field."""

    def test_default_is_none(self) -> None:
        receipt = make_receipt()
        assert receipt.credentialSubject.action.parameters_disclosure is None

    def test_round_trip_serialise_deserialise(self) -> None:
        receipt = make_receipt()
        receipt.credentialSubject.action.parameters_disclosure = {
            "path": "/tmp/foo.txt",
            "mode": "r",
        }

        dumped = receipt.model_dump(by_alias=True)
        action_dict = dumped["credentialSubject"]["action"]
        assert action_dict["parameters_disclosure"] == {
            "path": "/tmp/foo.txt",
            "mode": "r",
        }

        restored = AgentReceipt.model_validate(dumped)
        assert restored.credentialSubject.action.parameters_disclosure == {
            "path": "/tmp/foo.txt",
            "mode": "r",
        }

    def test_included_in_canonical_hash_when_present(self) -> None:
        """Setting parameters_disclosure must change the canonical hash."""
        baseline = make_receipt()
        baseline_hash = hash_receipt(baseline)

        with_disclosure = make_receipt()
        with_disclosure.credentialSubject.action.parameters_disclosure = {
            "path": "/tmp/foo.txt",
        }
        disclosure_hash = hash_receipt(with_disclosure)

        assert baseline_hash != disclosure_hash

    def test_omitted_from_canonical_hash_when_none(self) -> None:
        """When parameters_disclosure is None, hash matches a receipt without it."""
        r1 = make_receipt()
        r2 = make_receipt()
        r2.credentialSubject.action.parameters_disclosure = None
        assert hash_receipt(r1) == hash_receipt(r2)

    def test_canonical_hash_is_deterministic(self) -> None:
        r1 = make_receipt()
        r1.credentialSubject.action.parameters_disclosure = {"a": "1", "b": "2"}
        r2 = make_receipt()
        r2.credentialSubject.action.parameters_disclosure = {"a": "1", "b": "2"}
        assert hash_receipt(r1) == hash_receipt(r2)
