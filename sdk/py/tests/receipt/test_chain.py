"""Tests for chain verification."""

from unittest.mock import patch

from agent_receipts.receipt.chain import verify_chain
from agent_receipts.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from agent_receipts.receipt.hash import canonicalize, hash_receipt, sha256
from agent_receipts.receipt.signing import (
    generate_key_pair,
    sign_receipt,
)
from agent_receipts.receipt.types import (
    Chain,
    Issuer,
    Outcome,
    Principal,
)
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


def _build_chain(count: int, private_key: str) -> list:
    """Build a signed chain of `count` receipts."""
    chain = []
    previous_hash = None
    for i in range(1, count + 1):
        unsigned = make_unsigned(i, previous_hash)
        signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
        chain.append(signed)
        previous_hash = hash_receipt(signed)
    return chain


def _build_terminal_chain(count: int, private_key: str) -> list:
    """Build a chain of `count` receipts where the last has chain.terminal=True."""
    chain = _build_chain(count - 1, private_key)
    prev_hash = hash_receipt(chain[-1]) if chain else None
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:test"),
            principal=Principal(id="did:user:test"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=count,
                previous_receipt_hash=prev_hash,
                chain_id="chain_test",
            ),
            terminal=True,
        )
    )
    signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
    return [*chain, signed]


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


class TestAdr0008ChainBehaviours:
    """ADR-0008: response_hash, chain.terminal, and truncation detection."""

    # --- truncation pin ---

    def test_truncated_chain_is_valid_without_options(self) -> None:
        """Dropping tail receipts must not break verification (pins §7.3.1)."""
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        truncated = chain[:3]

        result = verify_chain(truncated, kp.public_key)
        assert result.valid is True
        assert result.length == 3

    # --- expected_length ---

    def test_expected_length_detects_truncation(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        truncated = chain[:3]

        result = verify_chain(truncated, kp.public_key, expected_length=5)
        assert result.valid is False

    def test_expected_length_passes_when_matches(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)

        result = verify_chain(chain, kp.public_key, expected_length=5)
        assert result.valid is True

    # --- expected_final_hash ---

    def test_expected_final_hash_detects_truncation(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        real_final_hash = hash_receipt(chain[-1])
        truncated = chain[:3]

        result = verify_chain(
            truncated, kp.public_key, expected_final_hash=real_final_hash
        )
        assert result.valid is False

    def test_expected_final_hash_passes_when_matches(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        final_hash = hash_receipt(chain[-1])

        result = verify_chain(chain, kp.public_key, expected_final_hash=final_hash)
        assert result.valid is True

    # --- terminal round-trip ---

    def test_terminal_chain_round_trips_as_valid(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key)
        assert result.valid is True
        assert chain[-1].credentialSubject.chain.terminal is True

    # --- receipt after terminal ---

    def test_receipt_after_terminal_is_always_invalid(self) -> None:
        kp = generate_key_pair()
        terminal_chain = _build_terminal_chain(3, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[-1])

        extra_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=4,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        extra_signed = sign_receipt(
            extra_unsigned, kp.private_key, "did:agent:test#key-1"
        )
        bad = [*terminal_chain, extra_signed]

        result = verify_chain(bad, kp.public_key)
        assert result.valid is False
        assert result.broken_at > -1

    def test_receipt_after_terminal_fires_unconditionally(self) -> None:
        """receipt-after-terminal must fire even with no caller options."""
        kp = generate_key_pair()
        terminal_chain = _build_terminal_chain(2, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[-1])

        extra_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=3,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        extra_signed = sign_receipt(
            extra_unsigned, kp.private_key, "did:agent:test#key-1"
        )

        result = verify_chain([*terminal_chain, extra_signed], kp.public_key)
        assert result.valid is False

    # --- require_terminal ---

    def test_require_terminal_passes_when_chain_ends_in_terminal(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key, require_terminal=True)
        assert result.valid is True

    def test_require_terminal_fails_when_terminal_receipt_dropped(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)
        truncated = chain[:2]  # drop terminal receipt

        result = verify_chain(truncated, kp.public_key, require_terminal=True)
        assert result.valid is False

    def test_require_terminal_not_set_non_terminal_is_valid(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key)  # no require_terminal
        assert result.valid is True

    # --- response_hash note ---

    def test_response_hash_note_set_when_hash_present_no_body(self) -> None:
        kp = generate_key_pair()
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body={"result": "ok"},
            )
        )
        signed = sign_receipt(unsigned, kp.private_key, "did:agent:test#key-1")

        result = verify_chain([signed], kp.public_key)
        assert result.valid is True
        assert result.response_hash_note != ""

    def test_no_response_hash_note_when_hash_absent(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(1, kp.private_key)

        result = verify_chain(chain, kp.public_key)
        assert result.valid is True
        assert result.response_hash_note == ""

    # --- create_receipt response_hash ---

    def test_create_receipt_computes_correct_response_hash(self) -> None:
        response_body = {"result": "ok", "status": 200}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body=response_body,
            )
        )
        expected = sha256(canonicalize(response_body))
        assert unsigned.credentialSubject.outcome.response_hash == expected

    def test_redact_then_hash_ordering(self) -> None:
        """Hash must equal hash(redacted), not hash(raw)."""
        raw_response = {"result": "ok", "password": "super-secret"}
        redacted_response = {"result": "ok", "password": "[REDACTED]"}

        hash_of_redacted = sha256(canonicalize(redacted_response))
        hash_of_raw = sha256(canonicalize(raw_response))
        assert hash_of_redacted != hash_of_raw

        # Caller pre-redacts and passes redacted body.
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body=redacted_response,
            )
        )

        assert unsigned.credentialSubject.outcome.response_hash == hash_of_redacted
        assert unsigned.credentialSubject.outcome.response_hash != hash_of_raw

    # --- terminal field presence ---

    def test_no_terminal_option_field_is_absent(self) -> None:
        """When terminal is not set, chain.terminal must be absent (None)."""
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                # terminal not set (defaults to False)
            )
        )
        assert unsigned.credentialSubject.chain.terminal is None

    def test_terminal_true_emits_terminal_field(self) -> None:
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                terminal=True,
            )
        )
        assert unsigned.credentialSubject.chain.terminal is True

    # --- response_bodies verification ---

    def test_response_bodies_matching_body_passes(self) -> None:
        """When the supplied body matches the stored hash, verification passes."""
        body = {"result": "ok", "status": 200}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-rb"
                ),
                response_body=body,
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={signed.id: body},
        )
        assert result.valid
        assert result.response_hash_note == ""

    def test_response_bodies_mismatch_fails(self) -> None:
        """When the supplied body does not match the stored hash, verification fails."""
        good_body = {"result": "ok"}
        bad_body = {"result": "tampered"}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-mm"
                ),
                response_body=good_body,
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={signed.id: bad_body},
        )
        assert not result.valid
        assert "response_hash mismatch" in result.error

    # --- hash compute errors ---

    def test_hash_failure_in_loop_populates_error(self) -> None:
        """hash_receipt raising on a previous receipt surfaces as a structured error.

        Patch hash_receipt to raise ValueError on every call. The first
        patched invocation occurs when the loop computes hash_receipt(previous)
        for receipt[1], which exercises the try/except at the per-receipt
        hash-link check.  verify_receipt is unaffected because it does not call
        hash_receipt — this isolates the try/except at the per-receipt
        hash-link check in verify_chain.
        """
        kp = generate_key_pair()
        chain = _build_chain(2, kp.private_key)

        with patch(
            "agent_receipts.receipt.chain.hash_receipt",
            side_effect=ValueError("injected hash failure"),
        ):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert result.broken_at == 1
        assert result.error.startswith("hash compute failed at index 0:")
        assert len(result.receipts) == 2
        assert result.receipts[1].hash_link_valid is False

    def test_hash_failure_in_expected_final_hash_populates_error(self) -> None:
        """hash_receipt raising on the final receipt surfaces via expected_final_hash.

        Patches hash_receipt to raise only when called on the last receipt's id,
        so the per-receipt loop succeeds (hash_receipt(previous) is called for
        earlier indices and returns normally) and the expected_final_hash branch
        triggers the new try/except.
        """
        kp = generate_key_pair()
        chain = _build_chain(2, kp.private_key)
        real_final_hash = hash_receipt(chain[-1])

        target_id = chain[-1].id
        real_hash_receipt = hash_receipt

        def selective_raise(r: object) -> str:
            if getattr(r, "id", None) == target_id:
                raise ValueError("injected hash failure on final receipt")
            return real_hash_receipt(r)  # type: ignore[arg-type]

        with patch(
            "agent_receipts.receipt.chain.hash_receipt",
            side_effect=selective_raise,
        ):
            result = verify_chain(
                chain,
                kp.public_key,
                expected_final_hash=real_final_hash,
            )

        assert result.valid is False
        assert result.broken_at == 1
        assert result.error.startswith("hash compute failed at index 1:")
        assert "injected hash failure" in result.error

    def test_response_bodies_absent_entry_emits_note(self) -> None:
        """When response_hash is present but receipt id is not in the map, emit note."""
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-note3"
                ),
                response_body={"result": "ok"},
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={},  # empty map — no entry for this receipt
        )
        assert result.valid
        assert result.response_hash_note != ""
