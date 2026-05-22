"""Unit tests for the ``pre_tool_call`` / ``post_tool_call`` handlers."""

from __future__ import annotations

import json
import time

from agent_receipts_hermes.hooks import (
    PENDING_MAX_AGE_S,
    PENDING_MAX_SIZE,
    HookState,
    _PendingCall,
    post_tool_call,
    pre_tool_call,
)
from tests.helpers import FakeEmitter


class TestPreToolCall:
    def test_emits_pending_frame(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        pre_tool_call(
            state,
            tool_name="read_file",
            args={"path": "/etc/hosts"},
            tool_call_id="tc-1",
        )
        assert len(fake_emitter.frames) == 1
        frame = fake_emitter.frames[0]
        assert frame.decision == "pending"
        assert frame.tool_name == "read_file"
        assert frame.channel == "hermes"
        assert frame.input is not None
        assert json.loads(frame.input) == {"path": "/etc/hosts"}

    def test_stashes_call_for_correlation(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        pre_tool_call(
            state,
            tool_name="bash",
            args={"command": "ls"},
            tool_call_id="tc-9",
            task_id="task-1",
            session_id="sess-1",
        )
        assert len(state.pending) == 1
        stashed = next(iter(state.pending.values()))
        assert stashed.tool_name == "bash"
        assert stashed.args == {"command": "ls"}

    def test_empty_tool_name_is_a_noop(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        pre_tool_call(state, tool_name="", args={"x": 1})
        assert state.pending == {}
        assert fake_emitter.frames == []

    def test_no_emitter_does_not_raise(self) -> None:
        state = HookState(emitter=None)
        pre_tool_call(state, tool_name="read_file", args={"path": "/x"})
        # Pending is still tracked so a follow-up post_tool_call can correlate.
        assert len(state.pending) == 1

    def test_unserialisable_args_do_not_drop_frame(
        self, fake_emitter: FakeEmitter
    ) -> None:
        class Unjsonable:
            pass

        state = HookState(emitter=fake_emitter)
        pre_tool_call(state, tool_name="read_file", args={"obj": Unjsonable()})
        # Frame still emitted; the JSON encoder's default falls back to a
        # ``repr()`` of the offending value rather than dropping the frame.
        assert len(fake_emitter.frames) == 1
        assert fake_emitter.frames[0].input is not None
        assert "Unjsonable" in fake_emitter.frames[0].input


class TestPostToolCall:
    def test_emits_allowed_frame_and_returns_classification(
        self, fake_emitter: FakeEmitter
    ) -> None:
        state = HookState(emitter=fake_emitter)
        pre_tool_call(
            state,
            tool_name="bash",
            args={"command": "echo hi"},
            tool_call_id="tc-1",
        )
        result = post_tool_call(
            state,
            tool_name="bash",
            args={"command": "echo hi"},
            result={"stdout": "hi"},
            tool_call_id="tc-1",
        )
        assert result is not None
        assert result.action_type == "system.command.execute"
        assert result.risk_level == "high"
        assert state.pending == {}

        decisions = [f.decision for f in fake_emitter.frames]
        assert decisions == ["pending", "allowed"]
        assert fake_emitter.frames[1].output is not None
        assert json.loads(fake_emitter.frames[1].output) == {"stdout": "hi"}

    def test_post_without_pre_still_emits(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        post_tool_call(
            state,
            tool_name="read_file",
            args={"path": "/x"},
            result={"content": "data"},
        )
        assert len(fake_emitter.frames) == 1
        assert fake_emitter.frames[0].decision == "allowed"

    def test_unknown_tool_emits_unknown_classification(
        self, fake_emitter: FakeEmitter
    ) -> None:
        state = HookState(emitter=fake_emitter)
        classification = post_tool_call(
            state, tool_name="zzz_no_such_tool", args={}, result={"x": 1}
        )
        assert classification is not None
        assert classification.action_type == "unknown"

    def test_error_propagated_into_frame(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        post_tool_call(
            state,
            tool_name="bash",
            args={"command": "false"},
            result=None,
            error="exit 1",
        )
        assert fake_emitter.frames[0].error == "exit 1"

    def test_emit_value_error_does_not_propagate(
        self, fake_emitter: FakeEmitter
    ) -> None:
        fake_emitter.raise_on["allowed"] = ValueError("frame too large")
        state = HookState(emitter=fake_emitter)
        # Must not raise — a single broken tool call cannot break the agent loop.
        post_tool_call(state, tool_name="read_file", args={"path": "/x"}, result=None)


class TestPendingEviction:
    def test_stale_entries_evicted_on_next_pre(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        # Seed an entry far past the eviction threshold.
        old_key = "old"
        state.pending[old_key] = _PendingCall(
            tool_name="read_file",
            args={},
            started_at=time.monotonic() - PENDING_MAX_AGE_S - 1.0,
            task_id="",
            session_id="",
        )
        pre_tool_call(state, tool_name="read_file", args={"path": "/y"})
        assert old_key not in state.pending

    def test_oversize_pending_map_is_capped(self, fake_emitter: FakeEmitter) -> None:
        state = HookState(emitter=fake_emitter)
        now = time.monotonic()
        # Fill past the cap with monotonically-increasing timestamps so the
        # eviction order is deterministic (oldest goes first).
        for i in range(PENDING_MAX_SIZE + 5):
            state.pending[f"k-{i}"] = _PendingCall(
                tool_name="read_file",
                args={},
                started_at=now + i * 1e-6,
                task_id="",
                session_id="",
            )
        pre_tool_call(state, tool_name="read_file", args={"path": "/y"})
        assert len(state.pending) <= PENDING_MAX_SIZE + 1
