"""Unit tests for the ``pre_tool_call`` / ``post_tool_call`` handlers."""

from __future__ import annotations

import json
import threading
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

    def test_unserialisable_args_drop_field_not_frame(
        self, fake_emitter: FakeEmitter
    ) -> None:
        class Unjsonable:
            def __repr__(self) -> str:
                # An attacker-controllable __repr__ MUST NOT influence
                # the signed audit trail — see _safe_json's docstring.
                return '{"forged_field": "MALICIOUS"}'

        state = HookState(emitter=fake_emitter)
        pre_tool_call(state, tool_name="read_file", args={"obj": Unjsonable()})
        # Frame still emitted but the unserialisable field is dropped,
        # and the malicious __repr__ does NOT appear in the wire payload.
        assert len(fake_emitter.frames) == 1
        frame = fake_emitter.frames[0]
        assert frame.input is None
        # Defence in depth: explicitly assert the forged payload is
        # nowhere in the recorded frame. Catches a regression that
        # smuggled repr() output into a new field (e.g. "input_repr")
        # or that emitted the string "None" instead of dropping.
        for field_value in (frame.input, frame.output, frame.error):
            assert "forged_field" not in (field_value or "")
            assert "MALICIOUS" not in (field_value or "")

    def test_bytes_args_decode_when_utf8(self, fake_emitter: FakeEmitter) -> None:
        # bytes are a common, well-defined case — decode for inclusion
        # rather than dropping the whole field.
        state = HookState(emitter=fake_emitter)
        pre_tool_call(state, tool_name="read_file", args={"blob": b"hello"})
        assert fake_emitter.frames[0].input is not None
        assert json.loads(fake_emitter.frames[0].input) == {"blob": "hello"}


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

    def test_emit_transport_error_does_not_propagate(
        self, fake_emitter: FakeEmitter
    ) -> None:
        # Newer agent-receipts releases raise EmitTransportError (a bare
        # Exception) by default when the daemon is unreachable (ADR-0025);
        # the pinned 0.9.0 swallows it. Either way the hook must not let a
        # transport failure surface into the host agent.
        class _FakeTransportError(Exception):
            pass

        fake_emitter.raise_on["allowed"] = _FakeTransportError("daemon down")
        state = HookState(emitter=fake_emitter)
        # Returns normally (does not raise) and still classifies — proving the
        # emit was attempted and its failure swallowed, not skipped.
        result = post_tool_call(state, tool_name="read_file", args={"path": "/x"})
        assert result is not None
        assert result.action_type == "filesystem.file.read"


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


class TestThreadSafety:
    def test_concurrent_pre_post_does_not_raise(
        self, fake_emitter: FakeEmitter
    ) -> None:
        """Multiple threads driving pre/post must not race the pending dict.

        Without the lock, ``_evict_stale`` iterating ``pending.items()``
        while another thread does ``pending[key] = ...`` or ``pending.pop()``
        would raise ``RuntimeError: dictionary changed size during iteration``.
        """
        state = HookState(emitter=fake_emitter)
        errors: list[Exception] = []
        start_barrier = threading.Barrier(8)

        def worker(worker_id: int) -> None:
            try:
                start_barrier.wait(timeout=2.0)
                for i in range(200):
                    tool_call_id = f"w{worker_id}-c{i}"
                    pre_tool_call(
                        state,
                        tool_name="read_file",
                        args={"path": f"/x/{worker_id}/{i}"},
                        tool_call_id=tool_call_id,
                    )
                    post_tool_call(
                        state,
                        tool_name="read_file",
                        args={"path": f"/x/{worker_id}/{i}"},
                        result={"ok": True},
                        tool_call_id=tool_call_id,
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True) for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
            assert not t.is_alive(), "worker thread hung"

        assert not errors, f"races raised: {errors[:3]}"
        # Every (pre, post) pair should have cleaned up its own entry.
        assert state.pending == {}
