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

`test_emitter_roundtrip_against_live_daemon` exercises the collector path. It
is SKIPPED unless AGENTRECEIPTS_SOCKET points at a *running* agent-receipts
daemon, because the daemon is a separately-built Go binary the SDK does not
ship. See audit/AUDIT_REPORT.md (Part 2) for how to stand one up.
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
def test_emitter_roundtrip_against_live_daemon():
    """Collector path: emit one event to a running daemon (fire-and-forget).

    The emit contract is fire-and-forget: a successful emit returns None and
    raises nothing. Verifying the receipt actually landed requires the
    `agent-receipts verify` CLI against the daemon's DB (out of band) — the
    SDK gives the caller no return value to assert on. That asymmetry is
    logged as a paper-cut in the audit report.
    """
    from agent_receipts import Emitter

    socket_path = os.environ["AGENTRECEIPTS_SOCKET"]
    with Emitter(socket_path=socket_path, session_id="audit-e2e") as e:
        assert e.session_id == "audit-e2e"
        ret = e.emit(
            channel="py-sdk",
            tool_name="filesystem.file.read",
            decision="allowed",
            input='{"path":"/etc/hosts"}',
            output='{"bytes":42}',
        )
        assert ret is None  # fire-and-forget, no ack


def test_emitter_no_daemon_is_silent_drop(tmp_path):
    """First-run-without-daemon contract: emit drops silently, never raises."""
    from agent_receipts import Emitter

    dead_socket = str(tmp_path / "nope.sock")
    with Emitter(socket_path=dead_socket, session_id="audit-drop") as e:
        # No daemon listening -> returns None, raises nothing, retains nothing.
        assert (
            e.emit(channel="py-sdk", tool_name="x.y", decision="allowed") is None
        )
