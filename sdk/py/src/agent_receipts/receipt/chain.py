"""Chain verification — validate receipt chains for integrity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agent_receipts.receipt.hash import hash_receipt
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


@dataclass
class ChainVerification:
    """Result of verifying an entire chain."""

    valid: bool
    length: int
    receipts: list[ReceiptVerification] = field(
        default_factory=list[ReceiptVerification]
    )
    broken_at: int = -1


def verify_chain(
    receipts: list[AgentReceipt],
    public_key: str,
) -> ChainVerification:
    """Verify a chain of signed receipts.

    Checks for each receipt:
    1. Ed25519 signature validity
    2. Hash linkage: previous_receipt_hash matches SHA-256 of prior receipt
    3. Sequence numbers are strictly incrementing

    Receipts must be provided in chain order (by sequence number).
    """
    if not receipts:
        return ChainVerification(valid=True, length=0)

    results: list[ReceiptVerification] = []
    broken_at = -1
    previous: AgentReceipt | None = None

    for i, receipt in enumerate(receipts):
        chain = receipt.credentialSubject.chain

        signature_valid = verify_receipt(receipt, public_key)

        if previous is None:
            hash_link_valid = chain.previous_receipt_hash is None
        else:
            previous_hash = hash_receipt(previous)
            hash_link_valid = chain.previous_receipt_hash == previous_hash

        current_sequence = chain.sequence
        if previous is None:
            sequence_valid = current_sequence >= 1
        else:
            prev_sequence = previous.credentialSubject.chain.sequence
            sequence_valid = current_sequence == prev_sequence + 1

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

    return ChainVerification(
        valid=broken_at == -1,
        length=len(receipts),
        receipts=results,
        broken_at=broken_at,
    )
