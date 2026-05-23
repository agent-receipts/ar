"""Tests for InMemoryEmitter: the test-double emitter."""

from __future__ import annotations

from agent_receipts.emitters import InMemoryEmitter
from tests.conftest import make_receipt


def test_starts_empty() -> None:
    e = InMemoryEmitter()
    assert e.received == []


def test_records_each_receipt_in_order() -> None:
    e = InMemoryEmitter()
    r1 = make_receipt(id="urn:r:1")
    r2 = make_receipt(id="urn:r:2")
    r3 = make_receipt(id="urn:r:3")
    e.emit(r1)
    e.emit(r2)
    e.emit(r3)
    assert [r.id for r in e.received] == ["urn:r:1", "urn:r:2", "urn:r:3"]


def test_clear_empties_received() -> None:
    e = InMemoryEmitter()
    e.emit(make_receipt(id="urn:r:1"))
    e.clear()
    assert e.received == []


def test_implements_emitter_protocol() -> None:
    # Light runtime check via the @runtime_checkable Protocol — this is the
    # contract every test-double must satisfy.
    from agent_receipts.emitters import Emitter

    e = InMemoryEmitter()
    assert isinstance(e, Emitter)
