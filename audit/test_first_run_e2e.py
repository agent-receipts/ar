"""End-to-end happy-path test for the agent-receipts Python SDK first run.

Codifies the path a brand-new adopter walks on day one, against the
*published* package surface only:

    python -m venv /tmp/ar-audit-venv
    source /tmp/ar-audit-venv/bin/activate
    pip install agent-receipts
    pip install pytest
    pytest audit/test_first_run_e2e.py -v

The core test (`test_in_process_happy_path`, `test_two_receipt_chain`) needs
nothing but `pip install agent-receipts` — no env vars, no daemon, no key
files. This is the flow the Python SDK README's Quick Start documents.

`test_daemon_emitter_roundtrip_against_live_daemon` exercises the local collector
path. It is SKIPPED unless AGENTRECEIPTS_SOCKET points at a *running*
agent-receipts daemon, because the daemon is a separately-built Go binary the SDK
does not ship. See audit/AUDIT_REPORT.md (Part 2) for how to stand one up.

Re-audit note (2026-05-24): targets sdk/py >= 0.10.0. The socket emitter was
renamed `Emitter` -> `DaemonEmitter` (ADR-0020); the top-level `Emitter` name is
now an un-instantiable Protocol. `test_wal_emitter_retains_on_failure` codifies
the v0.10.0 WAL fix; `test_emitter_protocol_runtime_checkable_footgun` pins the
DaemonEmitter/Protocol mismatch. See AUDIT_REPORT.md "Re-audit delta".
"""

from __future__ import annotations

import os
import socket

import pytest

from agent_receipts import (
    Chain,
    CreateReceiptInput,
    Issuer,
    Outcome,
    Principal,
    create_receipt,
    generate_key_pair,
    hash_receipt,
    sign_receipt,
    verify_chain,
    verify_receipt,
)
from agent_receipts.receipt.create import ActionInput

KEY_ID = "did:agent:my-agent#key-1"


def _sign_at(keys, sequence, previous_hash):
    """Create and sign one receipt at a given chain position."""
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:my-agent"),
            principal=Principal(id="did:user:alice"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=sequence,
                previous_receipt_hash=previous_hash,
                chain_id="chain_session-1",
            ),
        )
    )
    return sign_receipt(unsigned, keys.private_key, KEY_ID)


def test_in_process_happy_path():
    """README Quick Start: generate key, create, sign, hash, verify."""
    keys = generate_key_pair()

    receipt = _sign_at(keys, sequence=1, previous_hash=None)

    receipt_hash = hash_receipt(receipt)
    assert receipt_hash.startswith("sha256:")
    assert len(receipt_hash) == len("sha256:") + 64  # 32-byte digest, hex

    # Signature verifies against the matching public key.
    assert verify_receipt(receipt, keys.public_key) is True

    # And fails against a different key (tamper-evidence sanity check).
    other = generate_key_pair()
    assert verify_receipt(receipt, other.public_key) is False


def test_two_receipt_chain():
    """A 2-link chain verifies, and tampering with the link is detected."""
    keys = generate_key_pair()

    r1 = _sign_at(keys, sequence=1, previous_hash=None)
    r2 = _sign_at(keys, sequence=2, previous_hash=hash_receipt(r1))

    result = verify_chain([r1, r2], keys.public_key)
    assert result.valid is True
    assert result.length == 2

    # Out-of-order / broken link must NOT verify.
    broken = verify_chain([r2, r1], keys.public_key)
    assert broken.valid is False


def _daemon_is_live(path: str) -> bool:
    if not path:
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


@pytest.mark.skipif(
    not _daemon_is_live(os.environ.get("AGENTRECEIPTS_SOCKET", "")),
    reason="no live daemon at AGENTRECEIPTS_SOCKET; see AUDIT_REPORT.md Part 2",
)
def test_daemon_emitter_roundtrip_against_live_daemon():
    """Local collector path: emit one event to a running daemon (fire-and-forget).

    v0.10.0: the socket emitter is `DaemonEmitter` (was `Emitter` in 0.9.0).
    The emit contract is still fire-and-forget: a successful emit returns None
    and raises nothing. Confirming the receipt landed needs `agent-receipts
    verify`/`show` against the daemon DB (out of band) — the SDK gives no return
    value to assert on. That asymmetry is logged as a paper-cut in the report.
    """
    from agent_receipts import DaemonEmitter

    socket_path = os.environ["AGENTRECEIPTS_SOCKET"]
    with DaemonEmitter(socket_path=socket_path, session_id="audit-e2e") as e:
        assert e.session_id == "audit-e2e"
        ret = e.emit(
            channel="py-sdk",
            tool_name="filesystem.file.read",
            decision="allowed",
            input='{"path":"/etc/hosts"}',
            output='{"bytes":42}',
        )
        assert ret is None  # fire-and-forget, no ack


def test_daemon_emitter_no_daemon_is_silent_drop(tmp_path):
    """Local-path first-run-without-daemon: emit drops silently, never raises.

    STILL TRUE in v0.10.0 — the WAL fix does NOT cover this path (see
    test_wal_emitter_cannot_wrap_daemon_emitter).
    """
    from agent_receipts import DaemonEmitter

    dead_socket = str(tmp_path / "nope.sock")
    with DaemonEmitter(socket_path=dead_socket, session_id="audit-drop") as e:
        # No daemon listening -> returns None, raises nothing, retains nothing.
        assert (
            e.emit(channel="py-sdk", tool_name="x.y", decision="allowed") is None
        )


def test_top_level_emitter_is_now_a_protocol():
    """v0.10.0 breaking rename: `agent_receipts.Emitter` is a Protocol now.

    0.9.0 code `Emitter(socket_path=...)` raises a confusing TypeError. This
    pins the regression so the report's claim stays honest across versions.
    """
    from agent_receipts import Emitter

    assert getattr(Emitter, "_is_protocol", False) is True
    with pytest.raises(TypeError, match="Protocols cannot be instantiated"):
        Emitter(socket_path="/tmp/whatever.sock")  # type: ignore[call-arg]


def _signed_receipt():
    keys = generate_key_pair()
    return _sign_at(keys, sequence=1, previous_hash=None)


def test_wal_emitter_retains_on_failure_and_replays(tmp_path):
    """v0.10.0 WAL fix (#567): durable at-least-once for the HTTP/Protocol path.

    Contrasts with the DaemonEmitter silent-drop: a failed delivery is RETAINED
    in the WAL and replayed once the collector recovers — no silent loss.
    """
    from agent_receipts.emitters import FileWal, InMemoryEmitter, WalEmitter

    class _FailingEmitter:
        def emit(self, receipt):  # noqa: ANN001
            raise RuntimeError("collector down")

    wal_dir = str(tmp_path / "wal")
    receipt = _signed_receipt()

    # Collector down: emit surfaces the error AND retains the receipt.
    down = WalEmitter(inner=_FailingEmitter(), wal=FileWal(wal_dir))
    with pytest.raises(RuntimeError):
        down.emit(receipt)
    assert down.pending() == 1  # 0.9.0 would have lost this silently

    # Collector recovers: a fresh WalEmitter over the same dir replays the backlog.
    sink = InMemoryEmitter()
    up = WalEmitter(inner=sink, wal=FileWal(wal_dir))
    result = up.replay()
    assert result.delivered == 1
    assert result.remaining == 0
    assert up.pending() == 0


def test_wal_emitter_cannot_wrap_daemon_emitter(tmp_path):
    """Footgun: DaemonEmitter passes the runtime_checkable isinstance but its
    emit() signature is incompatible, so the WAL cannot protect the local path.
    """
    from agent_receipts import DaemonEmitter
    from agent_receipts.emitters import Emitter, FileWal, WalEmitter

    d = DaemonEmitter(socket_path=str(tmp_path / "x.sock"))
    # Structural isinstance is a FALSE positive — emit() arity differs.
    assert isinstance(d, Emitter) is True
    wrapped = WalEmitter(inner=d, wal=FileWal(str(tmp_path / "wal")))
    with pytest.raises(TypeError):
        wrapped.emit(_signed_receipt())
