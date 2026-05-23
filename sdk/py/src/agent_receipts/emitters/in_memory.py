"""InMemoryEmitter — array-backed test double (ADR-0020).

Performs no I/O and provides no delivery guarantee. Use in unit and
integration tests where the assertion is against the receipts that
passed through the emitter, not against a remote collector.

NOT for production use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_receipts.receipt.types import AgentReceipt


class InMemoryEmitter:
    """Captures emitted receipts in an exposed list. Test double only."""

    def __init__(self) -> None:
        self._received: list[AgentReceipt] = []

    @property
    def received(self) -> list[AgentReceipt]:
        """All receipts passed to :meth:`emit`, in arrival order.

        Returned as a live list reference for cheap test assertions; copy
        before mutating if you need an independent snapshot.
        """
        return self._received

    def emit(self, receipt: AgentReceipt) -> None:
        self._received.append(receipt)

    def clear(self) -> None:
        """Drop all recorded receipts. Useful between test cases."""
        self._received.clear()
