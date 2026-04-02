"""Tests for chain verification."""

from agent_receipts.receipt.chain import verify_chain
from agent_receipts.receipt.hash import hash_receipt
from agent_receipts.receipt.signing import (
    generate_key_pair,
    sign_receipt,
)
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


class TestVerifyChain:
    def test_empty_chain_is_valid(self) -> None:
        result = verify_chain([], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 0
        assert result.broken_at == -1

    def test_single_receipt_valid(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        result = verify_chain([signed], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 1

    def test_three_receipt_chain(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u2 = make_unsigned(2, h1)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h2 = hash_receipt(s2)

        u3 = make_unsigned(3, h2)
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2, s3], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 3
        assert result.broken_at == -1

    def test_tampered_receipt_detected(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        # Tamper with action type
        s1.credentialSubject.action.type = "filesystem.file.delete"

        result = verify_chain([s1], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 0
        assert result.receipts[0].signature_valid is False

    def test_broken_hash_link(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        fake_hash = "sha256:" + "0" * 64
        u2 = make_unsigned(2, fake_hash)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.receipts[1].hash_link_valid is False

    def test_broken_sequence(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u3 = make_unsigned(3, h1)  # Skips sequence 2
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s3], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.receipts[1].sequence_valid is False

    def test_wrong_key_fails(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        other_keys = generate_key_pair()
        result = verify_chain([s1], other_keys.public_key)
        assert result.valid is False
        assert result.receipts[0].signature_valid is False

    def test_continues_after_break(self) -> None:
        """Verification continues even after finding a broken receipt."""
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u2 = make_unsigned(2, h1)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        # Tamper
        s2.credentialSubject.action.type = "filesystem.file.delete"
        h2 = hash_receipt(s2)

        u3 = make_unsigned(3, h2)
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2, s3], TEST_PUBLIC_KEY)
        assert result.length == 3
        assert len(result.receipts) == 3
        assert result.broken_at == 1
