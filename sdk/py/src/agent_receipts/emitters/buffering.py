"""BufferingEmitter — in-memory batch buffer with timer flush (ADR-0020).

Wraps a downstream :class:`Emitter` and buffers receipts in memory,
flushing on a configurable interval or batch size.

The contract with the downstream emitter is per-receipt, NOT batched:
a flush calls ``inner.emit(receipt)`` once per buffered receipt.

!!! CRASH-LOSS RISK !!!
Buffered receipts are lost if the process exits before :meth:`flush`
completes. This emitter is NOT suitable for environments where audit
completeness is critical. Use a synchronous :class:`HttpEmitter` (or a
persistent WAL — tracked separately) when every receipt must reach the
collector.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_receipts.emitters.types import Emitter
    from agent_receipts.receipt.types import AgentReceipt


class BufferingEmitter:
    """Per-receipt batching wrapper around a downstream :class:`Emitter`.

    Parameters
    ----------
    inner:
        Downstream emitter. Each buffered receipt is delivered with a
        separate ``inner.emit(receipt)`` call when the buffer flushes.
    max_batch_size:
        Flush when the buffer reaches this many receipts. Must be >= 1.
    flush_interval_ms:
        Flush every N milliseconds while receipts are buffered. Must be
        >= 1. The interval timer only runs when at least one receipt is
        buffered — there is no idle-process tick.
    """

    def __init__(
        self,
        *,
        inner: Emitter,
        max_batch_size: int,
        flush_interval_ms: int,
    ) -> None:
        if max_batch_size < 1:
            raise ValueError("BufferingEmitter: max_batch_size must be >= 1")
        if flush_interval_ms < 1:
            raise ValueError("BufferingEmitter: flush_interval_ms must be >= 1")
        self._inner = inner
        self._max_batch_size = max_batch_size
        self._flush_interval = flush_interval_ms / 1000.0

        self._lock = threading.Lock()
        self._buffer: list[AgentReceipt] = []
        self._timer: threading.Timer | None = None
        self._closed = False

    def emit(self, receipt: AgentReceipt) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("BufferingEmitter: closed")
            self._buffer.append(receipt)
            if len(self._buffer) >= self._max_batch_size:
                # Drop the lock before flushing — downstream emit() may
                # take a long time and we don't want concurrent emit()
                # callers to stall on it.
                batch = self._buffer[:]
                self._buffer.clear()
                self._cancel_timer_locked()
            else:
                self._schedule_timer_locked()
                return
        self._deliver(batch)

    def flush(self) -> None:
        """Drain the buffer through the downstream emitter."""
        with self._lock:
            self._cancel_timer_locked()
            batch = self._buffer[:]
            self._buffer.clear()
        self._deliver(batch)

    def close(self) -> None:
        """Stop the interval timer and flush the remaining buffer."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cancel_timer_locked()
            batch = self._buffer[:]
            self._buffer.clear()
        self._deliver(batch)

    # ------------------------------------------------------------------

    def _deliver(self, batch: list[AgentReceipt]) -> None:
        # Per-receipt delivery: the inner contract is one receipt at a
        # time, not a batch on the wire.
        for receipt in batch:
            self._inner.emit(receipt)

    def _schedule_timer_locked(self) -> None:
        # Caller must hold self._lock. Idempotent: a running timer is
        # not replaced — emit() relies on the existing tick.
        if self._timer is not None:
            return
        t = threading.Timer(self._flush_interval, self._on_timer)
        t.daemon = True
        self._timer = t
        t.start()

    def _cancel_timer_locked(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _on_timer(self) -> None:
        with self._lock:
            self._timer = None
            if self._closed:
                return
            batch = self._buffer[:]
            self._buffer.clear()
        if batch:
            # Swallow downstream errors on the timer-driven path so they
            # don't propagate into the unrelated threading.Timer worker.
            # Production callers should rely on explicit flush()/close()
            # for error surfacing.
            try:
                self._deliver(batch)
            except Exception:  # noqa: BLE001 — timer thread must not crash on downstream errors
                pass
