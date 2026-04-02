"""Cross-language compatibility tests.

Verifies that the Python SDK produces identical outputs to the TypeScript SDK:
- Canonical JSON is byte-identical
- SHA-256 hashes match
- Signatures produced by TS can be verified by Python
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_receipts.receipt.hash import canonicalize, hash_receipt, sha256
from agent_receipts.receipt.signing import verify_receipt
from agent_receipts.receipt.types import AgentReceipt

FIXTURES = Path(__file__).parent / "fixtures"


def _load_vectors() -> dict:
    with open(FIXTURES / "ts_vectors.json") as f:
        return json.load(f)


class TestCanonicalizeMatchesTS:
    """Verify RFC 8785 canonicalization matches TypeScript output."""

    def test_simple_object(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["simpleInput"]
        expected = vectors["canonicalization"]["simpleExpected"]
        assert canonicalize(input_data) == expected

    def test_unsigned_receipt(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["receiptInput"]
        expected = vectors["canonicalization"]["receiptExpected"]
        assert canonicalize(input_data) == expected


class TestSha256MatchesTS:
    """Verify SHA-256 hashing matches TypeScript output."""

    def test_simple_string(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["hashing"]["simpleInput"]
        expected = vectors["hashing"]["simpleExpected"]
        assert sha256(input_data) == expected

    def test_receipt_hash(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        expected_hash = vectors["hashing"]["receiptExpected"]
        receipt = AgentReceipt(**signed_data)
        assert hash_receipt(receipt) == expected_hash


class TestVerifyTSSignature:
    """Verify that receipts signed by the TypeScript SDK verify in Python."""

    def test_ts_signature_verifies(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        assert verify_receipt(receipt, public_key) is True

    def test_ts_signature_fails_with_wrong_key(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        receipt = AgentReceipt(**signed_data)
        from agent_receipts.receipt.signing import generate_key_pair

        other_keys = generate_key_pair()
        assert verify_receipt(receipt, other_keys.public_key) is False

    def test_ts_signature_fails_when_tampered(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        receipt.credentialSubject.action.type = "filesystem.file.delete"
        assert verify_receipt(receipt, public_key) is False
