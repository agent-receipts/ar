"""hermes-agent ``pre_tool_call`` / ``post_tool_call`` handlers.

Under ADR-0010 (Flavor B) the daemon owns signing, hashing, chain state,
and persistence. The plugin's only job is to classify each tool call and
forward a frame to the daemon over its AF_UNIX socket. The :class:`HookState`
dataclass holds the small amount of per-instance state (the pending map +
the live emitter) so nothing is module-global.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from agent_receipts_hermes.classify import (
    DEFAULT_MAPPINGS,
    DEFAULT_PATTERNS,
    ClassificationResult,
    TaxonomyMapping,
    TaxonomyPattern,
    classify,
)

logger = logging.getLogger(__name__)

PENDING_MAX_AGE_S = 5 * 60.0
PENDING_MAX_SIZE = 1000

# hermes uses ``pre_tool_call``/``post_tool_call`` to bracket every tool
# call. ``decision`` mirrors the spec wire values.
_DECISION_PENDING = "pending"
_DECISION_ALLOWED = "allowed"


class EmitterLike(Protocol):
    """Minimal surface the hook code needs from the daemon emitter.

    Defined as a Protocol so tests can pass simple stub objects without
    constructing a real :class:`agent_receipts.emitter.Emitter`.
    """

    def emit(
        self,
        *,
        channel: str,
        tool_name: str,
        decision: str,
        tool_server: str = "",
        input: bytes | str | None = None,  # noqa: A002 - mirrors SDK API
        output: bytes | str | None = None,
        error: str = "",
    ) -> None: ...


@dataclass
class _PendingCall:
    tool_name: str
    args: Any
    started_at: float
    task_id: str
    session_id: str


@dataclass
class HookState:
    """Per-plugin-instance state passed into each hook handler.

    Avoids module-global mutable state so multiple hermes runtimes loading
    the plugin in the same process do not stomp on each other.

    ``pending`` is guarded by ``pending_lock`` because hermes may dispatch
    pre/post hook callbacks from worker threads (e.g. when subagents run
    in parallel). The lock is held only for the short read-modify-write
    on the dict — never across the emitter call, which is already
    thread-safe and may block briefly on socket I/O.
    """

    channel: str = "hermes"
    mappings: list[TaxonomyMapping] = field(
        default_factory=lambda: list(DEFAULT_MAPPINGS)
    )
    patterns: list[TaxonomyPattern] = field(
        default_factory=lambda: list(DEFAULT_PATTERNS)
    )
    emitter: EmitterLike | None = None
    pending: dict[str, _PendingCall] = field(default_factory=dict[str, _PendingCall])
    pending_lock: threading.Lock = field(default_factory=threading.Lock)


def _call_key(task_id: str, session_id: str, tool_call_id: str) -> str:
    task = task_id or "no-task"
    session = session_id or "no-session"
    call = tool_call_id or "no-id"
    return f"{task}::{session}::{call}"


def _evict_stale(pending: dict[str, _PendingCall]) -> None:
    """Drop entries older than ``PENDING_MAX_AGE_S`` and cap the map size.

    A tool that crashes before ``post_tool_call`` fires would otherwise leak
    its pending entry forever.
    """
    if not pending:
        return

    now = time.monotonic()
    stale = [k for k, v in pending.items() if now - v.started_at > PENDING_MAX_AGE_S]
    for k in stale:
        pending.pop(k, None)

    if len(pending) > PENDING_MAX_SIZE:
        ordered = sorted(pending.items(), key=lambda kv: kv[1].started_at)
        excess = len(pending) - PENDING_MAX_SIZE
        for k, _ in ordered[:excess]:
            pending.pop(k, None)


def _safe_json(value: Any) -> str | None:
    """Best-effort JSON serialisation; ``None`` if the value isn't representable.

    The audit trail is signed by the daemon, so anything we emit becomes a
    cryptographic claim about what the agent saw. We DO NOT fall back to
    ``repr()`` for unknown objects — an attacker-controllable ``__repr__``
    could otherwise inject misleading content into a trusted receipt.
    Instead we strictly serialise; ``bytes`` payloads are decoded as UTF-8
    (or noted as a length-only stub for non-UTF-8 binary), and any other
    unsupported type causes the whole field to be dropped. The frame
    itself still goes through, just without the offending payload.
    """
    if value is None:
        return None
    try:
        return json.dumps(value, default=_json_default)
    except (TypeError, ValueError) as exc:
        logger.debug("agent-receipts: dropping non-serialisable arg: %s", exc)
        return None


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {"__bytes__": len(value)}
    # Refuse arbitrary objects; raising TypeError tells json.dumps to fail,
    # which _safe_json then converts into a dropped field. Crucially we do
    # NOT call repr(value) here — see _safe_json's docstring.
    raise TypeError(
        f"agent-receipts: non-serialisable value of type {type(value).__name__!r}"
    )


def pre_tool_call(
    state: HookState,
    *,
    tool_name: str,
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> None:
    """Forward a ``pending`` frame to the daemon and stash the call context.

    The stash lets us re-emit the original ``args`` in the post handler in
    case the runtime forgot to thread them through.
    """
    if not tool_name:
        return

    key = _call_key(task_id, session_id, tool_call_id)
    # Take the lock for the whole read-modify-write on ``pending`` so a
    # concurrent pre/post on another thread cannot trip ``_evict_stale``
    # iterating the dict mid-mutation. The lock is released before the
    # emitter call so socket I/O never blocks other hooks.
    with state.pending_lock:
        _evict_stale(state.pending)
        state.pending[key] = _PendingCall(
            tool_name=tool_name,
            args=args,
            started_at=time.monotonic(),
            task_id=task_id,
            session_id=session_id,
        )

    _emit(
        state,
        tool_name=tool_name,
        decision=_DECISION_PENDING,
        args=args,
        result=None,
        error="",
    )


def post_tool_call(
    state: HookState,
    *,
    tool_name: str,
    args: Any = None,
    result: Any = None,
    error: str = "",
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> ClassificationResult | None:
    """Classify the call and forward an ``allowed`` frame to the daemon.

    Returns the classification result so callers and tests can inspect the
    decision without re-running ``classify``. Returns ``None`` for the
    no-tool-name guard.
    """
    if not tool_name:
        return None

    key = _call_key(task_id, session_id, tool_call_id)
    with state.pending_lock:
        stashed = state.pending.pop(key, None)

    effective_args = args if args is not None else (stashed.args if stashed else None)
    classification = classify(tool_name, state.mappings, state.patterns)

    logger.info(
        "agent-receipts: %s (%s, %s) → daemon",
        tool_name,
        classification.action_type,
        classification.risk_level,
    )

    _emit(
        state,
        tool_name=tool_name,
        decision=_DECISION_ALLOWED,
        args=effective_args,
        result=result,
        error=error,
    )

    return classification


def _emit(
    state: HookState,
    *,
    tool_name: str,
    decision: str,
    args: Any,
    result: Any,
    error: str,
) -> None:
    """Best-effort forward to the daemon. All failures are swallowed."""
    emitter = state.emitter
    if emitter is None:
        return

    input_json = _safe_json(args)
    output_json = _safe_json(result)

    try:
        emitter.emit(
            channel=state.channel,
            tool_name=tool_name,
            decision=decision,
            input=input_json,
            output=output_json,
            error=error,
        )
    except ValueError as exc:
        # Caller-bug-class errors from Emitter.emit (invalid JSON, oversized
        # frame, empty channel). Log and move on so a single broken tool call
        # cannot stop subsequent receipts from flowing.
        logger.warning("agent-receipts: emit failed (%s): %s", decision, exc)
    except RuntimeError as exc:
        # Emitter already closed — happens during shutdown; downgrade to debug.
        logger.debug("agent-receipts: emit dropped (%s): %s", decision, exc)
