"""Tests for BufferingEmitter: in-memory batching + interval flush."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest

from agent_receipts.emitters import BufferingEmitter, InMemoryEmitter
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from agent_receipts.receipt.types import AgentReceipt


class FailingEmitter:
    def emit(self, _receipt: AgentReceipt) -> None:
        raise RuntimeError("downstream failed")


def test_rejects_invalid_max_batch_size() -> None:
    with pytest.raises(ValueError, match="max_batch_size"):
        BufferingEmitter(
            inner=InMemoryEmitter(),
            max_batch_size=0,
            flush_interval_ms=50,
        )


def test_rejects_invalid_flush_interval() -> None:
    with pytest.raises(ValueError, match="flush_interval_ms"):
        BufferingEmitter(
            inner=InMemoryEmitter(),
            max_batch_size=2,
            flush_interval_ms=0,
        )


def test_does_not_flush_until_batch_fills() -> None:
    inner = InMemoryEmitter()
    buf = BufferingEmitter(
        inner=inner,
        max_batch_size=3,
        flush_interval_ms=10_000,
    )
    try:
        buf.emit(make_receipt(id="urn:r:1"))
        buf.emit(make_receipt(id="urn:r:2"))
        assert inner.received == []
        buf.emit(make_receipt(id="urn:r:3"))
        assert [r.id for r in inner.received] == ["urn:r:1", "urn:r:2", "urn:r:3"]
    finally:
        buf.close()


def test_flushes_on_interval() -> None:
    inner = InMemoryEmitter()
    flushed = threading.Event()

    class TrackingInner:
        def emit(self, receipt: AgentReceipt) -> None:
            inner.emit(receipt)
            flushed.set()

    buf = BufferingEmitter(
        inner=TrackingInner(),
        max_batch_size=100,
        flush_interval_ms=50,
    )
    try:
        buf.emit(make_receipt(id="urn:r:1"))
        # 50ms interval + scheduling latency: 1s deadline is plenty.
        assert flushed.wait(1.0), "buffer did not flush within 1s"
        assert [r.id for r in inner.received] == ["urn:r:1"]
    finally:
        buf.close()


def test_explicit_flush_drains_buffer() -> None:
    inner = InMemoryEmitter()
    buf = BufferingEmitter(
        inner=inner,
        max_batch_size=100,
        flush_interval_ms=10_000,
    )
    try:
        buf.emit(make_receipt(id="urn:r:1"))
        buf.emit(make_receipt(id="urn:r:2"))
        assert inner.received == []
        buf.flush()
        assert [r.id for r in inner.received] == ["urn:r:1", "urn:r:2"]
    finally:
        buf.close()


def test_delivers_one_per_receipt_not_batched() -> None:
    """The contract with downstream is per-receipt, not a batch on the wire."""
    inner = InMemoryEmitter()
    buf = BufferingEmitter(
        inner=inner,
        max_batch_size=4,
        flush_interval_ms=10_000,
    )
    try:
        for i in range(4):
            buf.emit(make_receipt(id=f"urn:r:{i}"))
        # Four individual receipts, not one bundled call.
        assert len(inner.received) == 4
    finally:
        buf.close()


def test_propagates_downstream_errors_via_flush() -> None:
    buf = BufferingEmitter(
        inner=FailingEmitter(),
        max_batch_size=100,
        flush_interval_ms=10_000,
    )
    try:
        buf.emit(make_receipt(id="urn:r:1"))
        with pytest.raises(RuntimeError, match="downstream failed"):
            buf.flush()
    finally:
        # close() also flushes — wrap so the test doesn't fail in teardown.
        try:
            buf.close()
        except RuntimeError:
            pass


def test_close_drains_and_rejects_further_emit() -> None:
    inner = InMemoryEmitter()
    buf = BufferingEmitter(
        inner=inner,
        max_batch_size=100,
        flush_interval_ms=10_000,
    )
    buf.emit(make_receipt(id="urn:r:1"))
    buf.close()
    assert [r.id for r in inner.received] == ["urn:r:1"]
    with pytest.raises(RuntimeError, match="closed"):
        buf.emit(make_receipt(id="urn:r:2"))


def test_timer_thread_swallows_downstream_errors() -> None:
    """An exception on the timer path must not crash the timer thread.

    Explicit flush() surfaces the error; the timer path swallows it so a
    daemon-Timer cannot tear down with an unhandled exception.
    """
    buf = BufferingEmitter(
        inner=FailingEmitter(),
        max_batch_size=100,
        flush_interval_ms=20,
    )
    try:
        buf.emit(make_receipt(id="urn:r:1"))
        # Wait long enough for the timer to fire and for its (swallowed)
        # exception to settle.
        time.sleep(0.1)
    finally:
        try:
            buf.close()
        except RuntimeError:
            pass
