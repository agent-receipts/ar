"""Fire-and-forget emitter for the agent-receipts daemon.

Forwards tool-call events to the agent-receipts daemon over a local Unix
domain socket. The emitter does NO crypto, NO canonicalisation, and holds NO
chain state — those live in the daemon per ADR-0010 (daemon process
separation, 2026-05-03).

Wire format: 4-byte big-endian length prefix followed by a UTF-8 JSON body.

Failure model: ``emit()`` MUST return quickly even when the daemon is not
running. Dial/write failures are logged at DEBUG level and ``None`` is
returned. Errors are only raised for caller bugs (empty channel, empty tool
name, invalid decision, invalid JSON in input/output, emitter already closed).
"""

from __future__ import annotations

import json
import logging
import math
import os
import platform
import socket
import struct
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import cast

logger = logging.getLogger(__name__)

# MaxFrameSize must agree with the daemon's socket.MaxFrameSize (1 MiB).
MAX_FRAME_SIZE = 1 << 20

# SupportedFrameVersion mirrors the daemon's pipeline.SupportedFrameVersion.
SUPPORTED_FRAME_VERSION = "1"

# Dial timeout: 25ms. Well under the fire-and-forget budget.
_DIAL_TIMEOUT = 0.025

# Write deadline: 100ms. Enforces the fire-and-forget contract.
_WRITE_TIMEOUT = 0.100

_VALID_DECISIONS = frozenset({"allowed", "denied", "pending"})


def default_socket_path() -> str:
    """Return the per-OS default path for the daemon socket.

    Resolution order:
    1. ``AGENTRECEIPTS_SOCKET`` environment variable (any platform).
    2. macOS: ``$TMPDIR/agentreceipts/events.sock`` (TMPDIR defaults to /tmp).
    3. Linux with ``$XDG_RUNTIME_DIR``: ``$XDG_RUNTIME_DIR/agentreceipts/events.sock``.
    4. Linux fallback: ``/run/agentreceipts/events.sock``.
    5. Other platforms: empty string (caller must supply path explicitly).
    """
    env = os.environ.get("AGENTRECEIPTS_SOCKET", "")
    if env:
        return env

    system = platform.system()
    if system == "Darwin":
        base = os.environ.get("TMPDIR") or "/tmp"
        return os.path.join(base, "agentreceipts", "events.sock")
    if system == "Linux":
        xdg = os.environ.get("XDG_RUNTIME_DIR", "")
        if xdg:
            return os.path.join(xdg, "agentreceipts", "events.sock")
        return "/run/agentreceipts/events.sock"
    return ""


class Emitter:
    """Fire-and-forget client for the agent-receipts daemon socket.

    Construct with :func:`Emitter`, fire events with :meth:`emit`, release
    the socket with :meth:`close`. Thread-safe: ``emit()`` may be called
    concurrently from multiple threads.

    The ``session_id`` is fixed for the lifetime of the emitter — even
    across daemon reconnects — per ADR-0010 OQ4.
    """

    def __init__(
        self,
        *,
        socket_path: str = "",
        session_id: str = "",
        log: logging.Logger | None = None,
    ) -> None:
        """Construct an Emitter.

        Parameters
        ----------
        socket_path:
            Override the daemon socket path. When empty, ``default_socket_path()``
            is used. Pass explicitly on platforms other than macOS/Linux.
        session_id:
            Stable session identifier. When empty, a UUID v4 is generated.
            Supply the host's session id so the emitter propagates it
            across every frame (ADR-0010 OQ4).
        log:
            Logger for drop diagnostics. Defaults to this module's logger.
            Pass ``logging.getLogger("null")`` (configured with NullHandler)
            to silence drop logs in tests.
        """
        if not socket_path:
            socket_path = default_socket_path()
        if not socket_path:
            raise ValueError(
                f"emitter: no default socket path on {platform.system()}; "
                "set AGENTRECEIPTS_SOCKET or pass socket_path="
            )
        self._socket_path = socket_path
        if session_id and not isinstance(session_id, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(
                f"emitter: session_id must be a str, got {type(session_id).__name__!r}"
            )
        self._session_id = session_id if session_id else str(uuid.uuid4())
        self._log = log if log is not None else logger

        self._lock = threading.Lock()
        self._conn: socket.socket | None = None
        self._closed = False

    @property
    def session_id(self) -> str:
        """Stable per-emitter session identifier (ADR-0010 OQ4)."""
        return self._session_id

    def emit(
        self,
        *,
        channel: str,
        tool_name: str,
        decision: str,
        tool_server: str = "",
        input: bytes | str | None = None,
        output: bytes | str | None = None,
        error: str = "",
    ) -> None:
        """Send one tool-call event to the daemon.

        Returns ``None`` even when the daemon is unreachable: dial and write
        failures are logged at DEBUG level and the socket is reset for
        re-dial on the next call. Errors are only raised for caller bugs
        that a retry could not fix.

        Parameters
        ----------
        channel:
            Required. Non-empty string identifying the SDK channel.
        tool_name:
            Required. Non-empty tool name.
        decision:
            Required. One of ``"allowed"``, ``"denied"``, or ``"pending"``.
        tool_server:
            Optional server qualifier for the tool.
        input:
            Optional raw JSON bytes or string. Passed verbatim to the daemon —
            NOT re-serialised. Must be valid JSON when non-empty.
        output:
            Optional raw JSON bytes or string. Same rules as ``input``.
        error:
            Optional error string.

        Raises
        ------
        ValueError
            For caller bugs: empty channel, empty tool_name, invalid decision,
            invalid JSON in input/output, or a serialised frame larger than
            ``MAX_FRAME_SIZE`` (1 MiB — the daemon's hard wire-protocol cap).
        RuntimeError
            When the emitter has been closed.
        """
        # --- validate caller inputs first (before acquiring lock) ---
        if not isinstance(channel, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(
                f"emitter: channel must be a str, got {type(channel).__name__!r}"
            )
        if not channel:
            raise ValueError("emitter: missing channel")
        if not isinstance(tool_name, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(
                f"emitter: tool_name must be a str, got {type(tool_name).__name__!r}"
            )
        if not tool_name:
            raise ValueError("emitter: missing tool_name")
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"emitter: invalid decision {decision!r} (want allowed|denied|pending)"
            )
        if not isinstance(tool_server, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(
                "emitter: tool_server must be a str,"
                f" got {type(tool_server).__name__!r}"
            )
        if not isinstance(error, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise ValueError(
                f"emitter: error must be a str, got {type(error).__name__!r}"
            )

        # Normalise input/output to bytes and validate JSON.
        raw_input = _to_raw_json(input, "input")
        raw_output = _to_raw_json(output, "output")

        # Build the frame dict.  Input/output are wrapped in _RawJSON so the
        # custom _encode_dict serialiser embeds them verbatim — no re-encoding.
        frame: dict[str, object] = {
            "v": SUPPORTED_FRAME_VERSION,
            "ts_emit": _now_rfc3339(),
            "session_id": self._session_id,
            "channel": channel,
            "tool": _build_tool(tool_name, tool_server),
            "decision": decision,
        }
        if raw_input is not None:
            frame["input"] = _RawJSON(raw_input)
        if raw_output is not None:
            frame["output"] = _RawJSON(raw_output)
        if error:
            frame["error"] = error

        body = _marshal_frame(frame)
        if len(body) > MAX_FRAME_SIZE:
            raise ValueError(
                f"emitter: frame too large: {len(body)} bytes (max {MAX_FRAME_SIZE})"
            )

        with self._lock:
            if self._closed:
                raise RuntimeError("emitter: closed")

            conn = self._dial_if_needed()
            if conn is None:
                return  # dial failure already logged

            if not self._write_frame(conn, body):
                # Write failure — close and clear so next emit re-dials.
                try:
                    conn.close()
                except OSError:
                    pass  # close errors during teardown are intentionally ignored
                self._conn = None

    def close(self) -> None:
        """Release the underlying socket connection.

        After ``close()``, subsequent ``emit()`` calls raise ``RuntimeError``.
        Safe to call multiple times.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._conn is not None:
                try:
                    self._conn.close()
                except OSError:
                    pass  # best-effort close; connection is being discarded regardless
                self._conn = None

    def __enter__(self) -> Emitter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Private helpers (must be called with self._lock held)
    # ------------------------------------------------------------------

    def _dial_if_needed(self) -> socket.socket | None:
        """Return the live connection, dialing if needed. Returns None on failure."""
        if self._conn is not None:
            return self._conn
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(_DIAL_TIMEOUT)
            conn.connect(self._socket_path)
        except OSError as exc:
            # Release the FD eagerly — without this, the half-open socket
            # would linger until garbage collection and we would leak FDs
            # on every emit() against a missing daemon.
            try:
                conn.close()
            except OSError:
                pass  # close errors on a failed dial are intentionally ignored
            self._log.debug(
                "agent-receipts emitter dropped event",
                extra={
                    "stage": "dial",
                    "socket": self._socket_path,
                    "err": str(exc),
                },
            )
            return None
        self._conn = conn
        return conn

    def _write_frame(self, conn: socket.socket, body: bytes) -> bool:
        """Write a length-prefixed frame. Returns True on success."""
        deadline = time.monotonic() + _WRITE_TIMEOUT
        try:
            header = struct.pack(">I", len(body))
            _send_all(conn, header, deadline)
            _send_all(conn, body, deadline)
            return True
        except OSError as exc:
            self._log.debug(
                "agent-receipts emitter dropped event",
                extra={
                    "stage": "write",
                    "socket": self._socket_path,
                    "err": str(exc),
                },
            )
            return False


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _send_all(conn: socket.socket, data: bytes, deadline: float) -> None:
    """Send all bytes against a single absolute monotonic deadline."""
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError("write deadline exceeded")
        conn.settimeout(remaining)
        n = conn.send(view[sent:])
        if n == 0:
            raise OSError("socket send returned 0 (connection closed)")
        sent += n


def _to_raw_json(value: bytes | str | None, field: str) -> bytes | None:
    """Normalise input/output to bytes and validate as JSON.

    Returns None for absent or empty values.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            raw = value.encode()
        except UnicodeEncodeError as exc:
            raise ValueError(f"emitter: {field} is not UTF-8 encoded: {exc}") from exc
    else:
        raw = bytes(value)
        # Reject non-UTF-8 bytes early: _encode_value does raw.decode() which
        # defaults to UTF-8, so non-UTF-8 input would raise UnicodeDecodeError
        # inside emit(), breaking the documented failure model.
        try:
            raw.decode()
        except UnicodeDecodeError as exc:
            raise ValueError(f"emitter: {field} is not UTF-8 encoded: {exc}") from exc
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"emitter: {field} is not valid JSON: {exc}") from exc
    _check_finite(parsed, field)
    return raw


def _check_finite(value: object, field: str) -> None:
    """Recursively reject non-finite floats (inf, -inf, nan).

    RFC 8785 canonicalisation rejects non-finite numbers, and Python's
    json.loads() accepts ``1e400`` as ``float('inf')``, so we must catch
    these before the frame reaches the daemon.
    """
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                f"emitter: {field} contains a non-finite number ({value!r})"
            )
    elif isinstance(value, dict):
        for v in cast("dict[str, object]", value).values():
            _check_finite(v, field)
    elif isinstance(value, list):
        for item in cast("list[object]", value):
            _check_finite(item, field)


def _build_tool(name: str, server: str) -> dict[str, str]:
    tool: dict[str, str] = {"name": name}
    if server:
        tool["server"] = server
    return tool


def _now_rfc3339() -> str:
    """Return current UTC time as RFC3339Nano with microsecond precision.

    The daemon parses ``ts_emit`` with Go's ``time.RFC3339Nano``, which accepts
    0–9 fractional-second digits. Python's stdlib only resolves to microseconds
    (6 digits); we pad with three trailing zeros so the wire format is visibly
    RFC3339Nano even when no nanosecond detail is available.
    """
    now = datetime.now(tz=UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}000Z"


class _RawJSON:
    """Wrapper that json.JSONEncoder serialises verbatim (no re-encoding)."""

    __slots__ = ("raw",)

    def __init__(self, raw: bytes) -> None:
        self.raw = raw


def _encode_value(v: object) -> str:
    """Serialise one frame value, passing _RawJSON through verbatim."""
    if isinstance(v, _RawJSON):
        return v.raw.decode()
    if isinstance(v, dict):
        return _encode_dict(cast("dict[str, object]", v))
    return json.dumps(v)


def _encode_dict(d: dict[str, object]) -> str:
    """Serialise a dict, embedding _RawJSON values verbatim."""
    parts = [f"{json.dumps(k)}:{_encode_value(v)}" for k, v in d.items()]
    return "{" + ",".join(parts) + "}"


def _marshal_frame(frame: dict[str, object]) -> bytes:
    """Serialise a frame dict, embedding _RawJSON values verbatim."""
    return _encode_dict(frame).encode()
