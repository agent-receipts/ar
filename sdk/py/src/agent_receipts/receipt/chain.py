"""Chain verification — validate receipt chains for integrity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agent_receipts.receipt.hash import canonicalize, hash_receipt, sha256
from agent_receipts.receipt.signing import verify_receipt

if TYPE_CHECKING:
    from agent_receipts.receipt.types import AgentReceipt


@dataclass
class ReceiptVerification:
    """Result of verifying a single receipt in a chain."""

    index: int
    receipt_id: str
    signature_valid: bool
    hash_link_valid: bool
    sequence_valid: bool


def _empty_receipts() -> list[ReceiptVerification]:
    """Typed default for ChainVerification.receipts (satisfies pyright strict)."""
    return []


@dataclass
class ChainVerification:
    """Result of verifying an entire chain."""

    valid: bool
    length: int
    receipts: list[ReceiptVerification] = field(default_factory=_empty_receipts)
    broken_at: int = -1
    error: str = ""
    # Non-empty when one or more receipts carry response_hash but no response
    # body was supplied for recomputation.
    response_hash_note: str = ""


def verify_chain(
    receipts: list[AgentReceipt],
    public_key: str,
    *,
    expected_length: int | None = None,
    expected_final_hash: str | None = None,
    require_terminal: bool = False,
    response_bodies: dict[str, object] | None = None,
) -> ChainVerification:
    """Verify a chain of signed receipts.

    Checks for each receipt:
    1. Ed25519 signature validity
    2. Hash linkage: previous_receipt_hash matches SHA-256 of prior receipt
    3. Sequence numbers are strictly incrementing
    4. Receipt-after-terminal: if any receipt has chain.terminal == True, no
       subsequent receipt may reference it (unconditional, spec §7.3.2)

    Chain verification does NOT detect tail truncation by default — dropping
    the last N receipts still produces valid=True. To detect truncation:

    - Supply expected_length and/or expected_final_hash (out-of-band witness)
    - Supply require_terminal for chains that must close with chain.terminal=True

    Chains that are open-ended and have no external witness cannot be detected
    as truncated. See spec §7.3.1 for the full treatment.

    Supply response_bodies (mapping receipt id → pre-redacted body) to verify
    outcome.response_hash fields. For each receipt whose id appears in the map,
    the hash is recomputed (canonicalize → SHA-256) and verification fails on
    mismatch. When the entry is absent an informational note is emitted instead.
    An absent body is not a verification failure.
    """
    if not receipts:
        if expected_length is not None and expected_length != 0:
            return ChainVerification(
                valid=False,
                length=0,
                broken_at=0,
                error=(
                    f"expected chain length does not match: "
                    f"expected {expected_length}, got 0"
                ),
            )
        return ChainVerification(valid=True, length=0)

    results: list[ReceiptVerification] = []
    broken_at = -1
    previous: AgentReceipt | None = None
    signature_compute_error: str | None = None

    for i, receipt in enumerate(receipts):
        chain = receipt.credentialSubject.chain

        try:
            signature_valid = verify_receipt(receipt, public_key)
        except (TypeError, ValueError) as exc:
            signature_valid = False
            if signature_compute_error is None:
                signature_compute_error = (
                    f"signature compute failed at index {i}: {exc}"
                )

        current_sequence = chain.sequence
        if previous is None:
            sequence_valid = current_sequence >= 1
        else:
            prev_sequence = previous.credentialSubject.chain.sequence
            sequence_valid = current_sequence == prev_sequence + 1

        if previous is None:
            hash_link_valid = chain.previous_receipt_hash is None
        else:
            try:
                previous_hash = hash_receipt(previous)
            except (TypeError, ValueError) as exc:
                results.append(
                    ReceiptVerification(
                        index=i,
                        receipt_id=receipt.id,
                        signature_valid=signature_valid,
                        hash_link_valid=False,
                        sequence_valid=sequence_valid,
                    )
                )
                return ChainVerification(
                    valid=False,
                    length=len(receipts),
                    receipts=results,
                    broken_at=i,
                    error=f"hash compute failed at index {i - 1}: {exc}",
                )
            hash_link_valid = chain.previous_receipt_hash == previous_hash

        verification = ReceiptVerification(
            index=i,
            receipt_id=receipt.id,
            signature_valid=signature_valid,
            hash_link_valid=hash_link_valid,
            sequence_valid=sequence_valid,
        )
        results.append(verification)

        if broken_at == -1 and (
            not signature_valid or not hash_link_valid or not sequence_valid
        ):
            broken_at = i

        previous = receipt

    # Signature-compute exception takes precedence over later structural checks:
    # if a receipt could not be canonicalised for verification, the chain is
    # already structurally broken and downstream checks (terminal placement,
    # response_hash, expected_length, ...) are not meaningful.
    if signature_compute_error is not None:
        return ChainVerification(
            valid=False,
            length=len(receipts),
            receipts=results,
            broken_at=broken_at,
            error=signature_compute_error,
        )

    # Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
    for i, receipt in enumerate(receipts[:-1]):
        if receipt.credentialSubject.chain.terminal is True:
            if broken_at == -1:
                broken_at = i + 1
            return ChainVerification(
                valid=False,
                length=len(receipts),
                receipts=results,
                broken_at=broken_at,
                error=(
                    f"receipt after terminal: receipt at index {i + 1} "
                    f"follows a terminal receipt at index {i}"
                ),
            )

    cv = ChainVerification(
        valid=broken_at == -1,
        length=len(receipts),
        receipts=results,
        broken_at=broken_at,
    )

    # Response-hash verification (spec §4.3.2).
    # When a body is supplied: recompute and fail on mismatch.
    # When the body is absent: emit an informational note only.
    bodies = response_bodies or {}
    for i, r in enumerate(receipts):
        expected_hash = r.credentialSubject.outcome.response_hash
        if expected_hash is None:
            continue
        body = bodies.get(r.id)
        if body is None:
            cv.response_hash_note = (
                "response_hash present in one or more receipts; "
                "response body not supplied — hash cannot be verified offline"
            )
            continue
        if not cv.valid:
            continue
        canonical = canonicalize(body)
        computed = sha256(canonical)
        if computed != expected_hash:
            cv.valid = False
            cv.broken_at = i
            cv.error = (
                f"response_hash mismatch at index {i}: "
                f"receipt has {expected_hash}, body hashes to {computed}"
            )
            return cv

    if not cv.valid:
        return cv

    # Optional out-of-band checks (only when basic verification passes).
    if expected_length is not None and len(receipts) != expected_length:
        cv.valid = False
        cv.broken_at = len(receipts) - 1
        cv.error = (
            f"expected chain length does not match: "
            f"expected {expected_length}, got {len(receipts)}"
        )
        return cv

    if expected_final_hash is not None:
        last_index = len(receipts) - 1
        try:
            last_hash = hash_receipt(receipts[-1])
        except (TypeError, ValueError) as exc:
            cv.valid = False
            cv.broken_at = last_index
            cv.error = f"hash compute failed at index {last_index}: {exc}"
            return cv
        if last_hash != expected_final_hash:
            cv.valid = False
            cv.broken_at = last_index
            cv.error = "final receipt hash does not match expected value"
            return cv

    if require_terminal:
        last = receipts[-1]
        if last.credentialSubject.chain.terminal is not True:
            cv.valid = False
            cv.broken_at = len(receipts) - 1
            cv.error = (
                "require_terminal: last receipt does not have chain.terminal: True"
            )
            return cv

    return cv
