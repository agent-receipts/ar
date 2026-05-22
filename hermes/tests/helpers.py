"""Shared test doubles for the hermes plugin test suite."""

from __future__ import annotations

import os
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RecordedFrame:
    """One frame captured by :class:`FakeEmitter` or :class:`FakeSocketServer`."""

    channel: str
    tool_name: str
    decision: str
    input: str | None = None
    output: str | None = None
    error: str = ""


@dataclass
class FakeEmitter:
    """In-process stand-in for :class:`agent_receipts.emitter.Emitter`.

    Captures every ``emit`` call so tests can assert on the wire frames
    without spinning up a real Unix socket. Implements the structural
    ``EmitterLike`` Protocol the hook code depends on.
    """

    frames: list[RecordedFrame] = field(default_factory=list)
    raise_on: dict[str, Exception] = field(default_factory=dict)

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
    ) -> None:
        del tool_server  # part of the SDK signature but unused by the fake
        if decision in self.raise_on:
            raise self.raise_on[decision]
        self.frames.append(
            RecordedFrame(
                channel=channel,
                tool_name=tool_name,
                decision=decision,
                input=_as_str(input),
                output=_as_str(output),
                error=error,
            )
        )


def _as_str(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


class FakeSocketServer:
    """Accept frames from a real :class:`Emitter` over an AF_UNIX socket.

    Used by the integration test to exercise the full plugin → daemon
    wire path end-to-end. Frames arrive as a 4-byte big-endian length
    prefix followed by a UTF-8 JSON body; we mirror the daemon's parsing
    so a malformed frame fails the test instead of hanging.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.frames: list[bytes] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(path)
        self._sock.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.25)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(1.0)
            while not self._stop.is_set():
                header = _recv_exact(conn, 4)
                if header is None:
                    return
                (length,) = struct.unpack(">I", header)
                body = _recv_exact(conn, length)
                if body is None:
                    return
                self.frames.append(body)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class FakeCtx:
    """Minimal stand-in for the hermes plugin ``ctx`` object.

    Captures hook + tool registrations so tests can introspect them.
    """

    def __init__(
        self,
        plugin_config: dict[str, Any] | None = None,
        *,
        expose_register_tool: bool = True,
    ) -> None:
        self.plugin_config = plugin_config or {}
        self.hooks: dict[str, Any] = {}
        self.tools: list[dict[str, Any]] = []
        self._expose_register_tool = expose_register_tool

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback

    def __getattr__(self, name: str) -> Any:
        if name == "register_tool" and self._expose_register_tool:
            return self._register_tool
        raise AttributeError(name)

    def _register_tool(self, **kwargs: Any) -> None:
        self.tools.append(kwargs)
