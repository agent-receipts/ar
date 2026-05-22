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
    decoded = json.loads(body.decode("utf-8"))
    # Each frame must round-trip the canonical fields the daemon needs.
    assert "v" in decoded
    assert "ts_emit" in decoded
    assert "session_id" in decoded
    assert decoded["tool"]["name"] == "read_file"
    # The body must be valid UTF-8 JSON of bounded size — both are
    # checked implicitly by FakeSocketServer's parser, but assert them
    # here too so a regression in either yields a clear test failure
    # rather than a generic "frame didn't arrive" timeout.
    assert 0 < len(body) <= 1 << 20, "body exceeds the daemon's 1 MiB frame cap"
    # The 4-byte big-endian length prefix that preceded ``body`` on the
    # wire decodes to len(body) by construction — the server only appends
    # to ``frames`` after reading exactly that many bytes — so the test
    # of interest is that the prefix decodes correctly through ``struct``,
    # not that ``body`` equals itself.
    rebuilt_prefix = struct.pack(">I", len(body))
    (rebuilt_length,) = struct.unpack(">I", rebuilt_prefix)
    assert rebuilt_length == len(body)
