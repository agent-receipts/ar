"""End-to-end plugin lifecycle: ``register`` → hooks → fake daemon socket.

These tests boot the real :class:`agent_receipts.emitter.Emitter` against
an in-process AF_UNIX server so we exercise the same wire path operators
will see at runtime: frame layout, JSON body, fire-and-forget semantics.
"""

from __future__ import annotations

import json
import struct

from agent_receipts_hermes import register
from tests.helpers import FakeCtx, FakeSocketServer


def _decode_frames(raw_frames: list[bytes]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for body in raw_frames:
        out.append(json.loads(body.decode("utf-8")))
    return out


def _wait_for_frames(
    server: FakeSocketServer, expected: int, *, timeout_s: float = 2.0
) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if len(server.frames) >= expected:
            return
        time.sleep(0.01)


def test_pre_and_post_hooks_round_trip_to_daemon(
    tmp_socket: FakeSocketServer,
) -> None:
    ctx = FakeCtx({"socketPath": tmp_socket.path})
    state = register(ctx)

    assert "pre_tool_call" in ctx.hooks
    assert "post_tool_call" in ctx.hooks
    tool_names = {t["name"] for t in ctx.tools}
    assert tool_names == {"ar_query_receipts", "ar_verify_chain"}

    ctx.hooks["pre_tool_call"](
        tool_name="bash",
        args={"command": "echo integration"},
        tool_call_id="tc-1",
        task_id="task-1",
        session_id="sess-1",
    )
    ctx.hooks["post_tool_call"](
        tool_name="bash",
        args={"command": "echo integration"},
        result={"stdout": "integration"},
        tool_call_id="tc-1",
        task_id="task-1",
        session_id="sess-1",
    )

    _wait_for_frames(tmp_socket, expected=2)

    frames = _decode_frames(tmp_socket.frames)
    assert len(frames) == 2

    decisions = [f["decision"] for f in frames]
    assert decisions == ["pending", "allowed"]

    for frame in frames:
        assert frame["channel"] == "hermes"
        assert frame["tool"] == {"name": "bash"}
        assert frame["v"] == "1"
        assert frame["session_id"]  # emitter generated a session id

    # The pending map should be empty after a matching post call.
    assert state.pending == {}

    # The "allowed" frame must carry the output JSON verbatim.
    output = frames[1]["output"]
    assert output is not None
    assert json.loads(json.dumps(output))["stdout"] == "integration"


def test_disabled_config_skips_hook_registration(
    tmp_socket: FakeSocketServer,
) -> None:
    ctx = FakeCtx({"enabled": False, "socketPath": tmp_socket.path})
    register(ctx)
    assert ctx.hooks == {}
    assert ctx.tools == []


def test_adversarial_repr_never_reaches_wire(
    tmp_socket: FakeSocketServer,
) -> None:
    """A malicious ``__repr__`` MUST NOT appear in the on-wire frame.

    This complements the unit test in test_hooks.py: that one asserts
    on the in-memory ``FakeEmitter`` capture, this one inspects the raw
    bytes the real ``agent_receipts.emitter.Emitter`` actually wrote to
    the socket. A regression that bypassed ``_safe_json`` (e.g. by
    forwarding the args dict to ``Emitter.emit`` unchanged) would slip
    past the unit test but fail this one.
    """

    class Unjsonable:
        def __repr__(self) -> str:
            return '{"forged_field": "MALICIOUS"}'

    ctx = FakeCtx({"socketPath": tmp_socket.path})
    register(ctx)
    ctx.hooks["pre_tool_call"](
        tool_name="read_file",
        args={"obj": Unjsonable()},
        tool_call_id="tc-1",
    )
    _wait_for_frames(tmp_socket, expected=1)

    body = tmp_socket.frames[0]
    decoded_text = body.decode("utf-8")
    assert "forged_field" not in decoded_text
    assert "MALICIOUS" not in decoded_text

    # The frame should still be well-formed JSON without an `input` field
    # (or with an empty input). The agent's other observable state — tool
    # name, decision — must still arrive so the daemon records the call.
    decoded = json.loads(decoded_text)
    assert decoded["tool"]["name"] == "read_file"
    assert decoded["decision"] == "pending"
    assert "input" not in decoded


def test_emitter_drops_silently_when_socket_unreachable(
    tmp_path: object,
) -> None:
    # Point the plugin at a socket path that doesn't exist so the emitter
    # has to fail open. The hooks must still run without raising.
    ctx = FakeCtx({"socketPath": "/tmp/does-not-exist/agentreceipts.sock"})  # noqa: S108
    register(ctx)

    ctx.hooks["pre_tool_call"](
        tool_name="read_file", args={"path": "/x"}, tool_call_id="tc-1"
    )
    ctx.hooks["post_tool_call"](
        tool_name="read_file",
        args={"path": "/x"},
        result={"content": "hi"},
        tool_call_id="tc-1",
    )


def test_frame_layout_matches_daemon_wire_protocol(
    tmp_socket: FakeSocketServer,
) -> None:
    ctx = FakeCtx({"socketPath": tmp_socket.path})
    register(ctx)
    ctx.hooks["pre_tool_call"](
        tool_name="read_file", args={"path": "/etc/hosts"}, tool_call_id="tc-1"
    )
    _wait_for_frames(tmp_socket, expected=1)

    body = tmp_socket.frames[0]
    header = tmp_socket.headers[0]
    decoded = json.loads(body.decode("utf-8"))

    # Each frame must round-trip the canonical fields the daemon needs.
    assert "v" in decoded
    assert "ts_emit" in decoded
    assert "session_id" in decoded
    assert decoded["tool"]["name"] == "read_file"

    # Body must be valid UTF-8 JSON of bounded size — the daemon caps
    # frames at 1 MiB (sdk/py emitter.MAX_FRAME_SIZE).
    assert 0 < len(body) <= 1 << 20

    # The 4-byte header was captured separately from the body by the
    # fake server (before recv'ing the body), so this comparison is a
    # real check that the emitter emitted the prefix it claimed to —
    # not the previous tautology of `pack(len(body)) == pack(len(body))`.
    assert len(header) == 4
    (advertised_length,) = struct.unpack(">I", header)
    assert advertised_length == len(body), (
        f"length prefix {advertised_length} disagrees with body length {len(body)}"
    )
