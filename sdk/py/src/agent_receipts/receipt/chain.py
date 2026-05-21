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


# Chain termination status values (spec §7.3.3).
STATUS_COMPLETE = "complete"
STATUS_INTERRUPTED = "interrupted"
STATUS_UNKNOWN = "unknown"


def _classify_termination_status(receipts: list[AgentReceipt]) -> str:
    """Inspect the final receipt and return the chain's termination status.

    Independent of verification result — describes what the chain claims on
    the wire, not whether it is valid. See spec §7.3.3.
    """
    if not receipts:
        return STATUS_UNKNOWN
    last = receipts[-1]
    ch = last.credentialSubject.chain
    if ch.terminal is not True:
        return STATUS_UNKNOWN
    if ch.status == STATUS_INTERRUPTED:
        return STATUS_INTERRUPTED
    return STATUS_COMPLETE


@dataclass
class ChainVerification:
    """Result of verifying an entire chain."""

    valid: bool
    length: int
    # "complete" | "interrupted" | "unknown" (spec §7.3.3).
    status: str = STATUS_UNKNOWN
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
    5. Chain identifier binding: all receipts MUST share the same
       chain.chain_id as the first receipt (unconditional, spec §7.3.4)

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
                status=STATUS_UNKNOWN,
                broken_at=0,
                error=(
                    f"expected chain length does not match: "
                    f"expected {expected_length}, got 0"
                ),
            )
        return ChainVerification(valid=True, length=0, status=STATUS_UNKNOWN)

    status = _classify_termination_status(receipts)

    results: list[ReceiptVerification] = []
    broken_at = -1
    previous: AgentReceipt | None = None
    signature_compute_error: str | None = None
    signature_compute_error_at: int = -1
    hash_compute_error: str | None = None
    hash_compute_error_at: int = -1

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
                signature_compute_error_at = i

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
                hash_link_valid = chain.previous_receipt_hash == previous_hash
            except (TypeError, ValueError) as exc:
                if hash_compute_error is None:
                    hash_compute_error = f"hash compute failed at index {i - 1}: {exc}"
                    hash_compute_error_at = i
                hash_link_valid = False

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

    # Pick the compute error that occurred earliest in the chain.
    # When both are present, the one at the lower index wins (not always sig).
    # Compute this before the terminal check so early returns can compare indices.
    loop_error = ""
    loop_error_at = -1
    if signature_compute_error is not None and hash_compute_error is not None:
        if signature_compute_error_at <= hash_compute_error_at:
            loop_error = signature_compute_error
            loop_error_at = signature_compute_error_at
        else:
            loop_error = hash_compute_error
            loop_error_at = hash_compute_error_at
    elif signature_compute_error is not None:
        loop_error = signature_compute_error
        loop_error_at = signature_compute_error_at
    elif hash_compute_error is not None:
        loop_error = hash_compute_error
        loop_error_at = hash_compute_error_at

    # Chain identifier binding check (unconditional — spec §7.3.4).
    # All receipts in a verified chain MUST share chain.chain_id. Reject
    # cross-chain splices: an attacker with a valid hash linkage might
    # otherwise mix receipts from two distinct chains under one verification
    # call. Runs independently of hash linkage so a forged link still fails
    # here.
    expected_chain_id = receipts[0].credentialSubject.chain.chain_id
    for i in range(1, len(receipts)):
        observed = receipts[i].credentialSubject.chain.chain_id
        if observed != expected_chain_id:
            # broken_at aligns with the error message — set unconditionally to
            # the mismatch index so callers reading broken_at and error see the
            # same offending receipt. (Any earlier per-receipt failure already
            # surfaces in the per-receipt receipts list.)
            quoted_expected = f'"{expected_chain_id}"'
            quoted_observed = f'"{observed}"'
            return ChainVerification(
                valid=False,
                length=len(receipts),
                status=status,
                receipts=results,
                broken_at=i,
                error=(
                    f"chain_id mismatch at index {i}: "
                    f"expected {quoted_expected}, got {quoted_observed}"
                ),
            )

    # Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
    for i, receipt in enumerate(receipts[:-1]):
        if receipt.credentialSubject.chain.terminal is True:
            terminal_violation_at = i + 1
            if broken_at == -1 or terminal_violation_at < broken_at:
                broken_at = terminal_violation_at
            # Use compute-error message only when the error preceded the terminal
            # violation; otherwise the terminal violation message takes priority.
            if loop_error and loop_error_at <= terminal_violation_at:
                error_msg = loop_error
            else:
                error_msg = (
                    f"receipt after terminal: receipt at index {i + 1} "
                    f"follows a terminal receipt at index {i}"
                )
            return ChainVerification(
                valid=False,
                length=len(receipts),
                status=status,
                receipts=results,
                broken_at=broken_at,
                error=error_msg,
            )

    cv = ChainVerification(
        valid=broken_at == -1,
        length=len(receipts),
        status=status,
        receipts=results,
        broken_at=broken_at,
        error=loop_error,
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
            cv.error = (
                f"final receipt hash mismatch at index {last_index}: "
                f"expected {expected_final_hash}, got {last_hash}"
            )
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
