"""Tests for the SQLite receipt store."""

from __future__ import annotations

import pytest

from agent_receipts.receipt.hash import hash_receipt
from agent_receipts.store.store import ReceiptQuery, ReceiptStore, open_store
from tests.conftest import make_receipt


def test_open_store_creates_db() -> None:
    store = open_store(":memory:")
    assert isinstance(store, ReceiptStore)
    store.close()


def test_insert_and_get_by_id() -> None:
    store = open_store(":memory:")
    receipt = make_receipt()
    receipt_hash = hash_receipt(receipt)
    store.insert(receipt, receipt_hash)

    result = store.get_by_id(receipt.id)
    assert result is not None
    assert result.id == receipt.id
    assert result.credentialSubject.action.type == "filesystem.file.read"
    store.close()


def test_get_by_id_not_found_returns_none() -> None:
    store = open_store(":memory:")
    assert store.get_by_id("urn:receipt:nonexistent") is None
    store.close()


def test_insert_and_get_chain() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:c1-1", chain_id="chain-1", sequence=1)
    r2 = make_receipt(
        id="urn:receipt:c1-2",
        chain_id="chain-1",
        sequence=2,
        previous_hash=hash_receipt(r1),
    )
    r3 = make_receipt(
        id="urn:receipt:c1-3",
        chain_id="chain-1",
        sequence=3,
        previous_hash=hash_receipt(r2),
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r3, hash_receipt(r3))  # insert out of order
    store.insert(r2, hash_receipt(r2))

    chain = store.get_chain("chain-1")
    assert len(chain) == 3
    assert [r.credentialSubject.chain.sequence for r in chain] == [1, 2, 3]
    store.close()


def test_get_chain_empty() -> None:
    store = open_store(":memory:")
    assert store.get_chain("no-such-chain") == []
    store.close()


def test_query_by_chain_id() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:q1", chain_id="chain-a", sequence=1)
    r2 = make_receipt(id="urn:receipt:q2", chain_id="chain-b", sequence=1)
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(chain_id="chain-a"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:q1"
    store.close()


def test_query_by_action_type() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:a1", action_type="fs.read", chain_id="ca1", sequence=1
    )
    r2 = make_receipt(
        id="urn:receipt:a2", action_type="net.request", chain_id="ca2", sequence=1
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(action_type="net.request"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:a2"
    store.close()


def test_query_by_risk_level() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:r1", risk_level="low", chain_id="cr1", sequence=1)
    r2 = make_receipt(
        id="urn:receipt:r2", risk_level="high", chain_id="cr2", sequence=1
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(risk_level="high"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:r2"
    store.close()


def test_query_by_status() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(id="urn:receipt:s1", status="success", chain_id="cs1", sequence=1)
    r2 = make_receipt(id="urn:receipt:s2", status="failure", chain_id="cs2", sequence=1)
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))

    results = store.query(ReceiptQuery(status="failure"))
    assert len(results) == 1
    assert results[0].id == "urn:receipt:s2"
    store.close()


def test_query_by_time_range() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:t1",
        timestamp="2026-01-01T00:00:00Z",
        chain_id="ct1",
        sequence=1,
    )
    r2 = make_receipt(
        id="urn:receipt:t2",
        timestamp="2026-06-15T00:00:00Z",
        chain_id="ct2",
        sequence=1,
    )
    r3 = make_receipt(
        id="urn:receipt:t3",
        timestamp="2026-12-31T00:00:00Z",
        chain_id="ct3",
        sequence=1,
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))
    store.insert(r3, hash_receipt(r3))

    results = store.query(
        ReceiptQuery(after="2026-03-01T00:00:00Z", before="2026-09-01T00:00:00Z")
    )
    assert len(results) == 1
    assert results[0].id == "urn:receipt:t2"
    store.close()


def test_query_with_limit() -> None:
    store = open_store(":memory:")
    for i in range(5):
        r = make_receipt(id=f"urn:receipt:l{i}", sequence=i + 1)
        store.insert(r, hash_receipt(r))

    results = store.query(ReceiptQuery(limit=2))
    assert len(results) == 2
    store.close()


def test_query_no_filters() -> None:
    store = open_store(":memory:")
    for i in range(3):
        r = make_receipt(id=f"urn:receipt:n{i}", sequence=i + 1)
        store.insert(r, hash_receipt(r))

    results = store.query(ReceiptQuery())
    assert len(results) == 3
    store.close()


def test_stats() -> None:
    store = open_store(":memory:")
    r1 = make_receipt(
        id="urn:receipt:st1",
        chain_id="c1",
        sequence=1,
        risk_level="low",
        status="success",
        action_type="fs.read",
    )
    r2 = make_receipt(
        id="urn:receipt:st2",
        chain_id="c1",
        sequence=2,
        risk_level="high",
        status="failure",
        action_type="net.request",
    )
    r3 = make_receipt(
        id="urn:receipt:st3",
        chain_id="c2",
        sequence=1,
        risk_level="low",
        status="success",
        action_type="fs.read",
    )
    store.insert(r1, hash_receipt(r1))
    store.insert(r2, hash_receipt(r2))
    store.insert(r3, hash_receipt(r3))

    s = store.stats()
    assert s.total == 3
    assert s.chains == 2
    assert len(s.by_risk) == 2
    assert len(s.by_status) == 2
    assert len(s.by_action) == 2
    store.close()


def test_close() -> None:
    store = open_store(":memory:")
    store.close()
    with pytest.raises(Exception):  # noqa: B017
        store.get_by_id("test")
