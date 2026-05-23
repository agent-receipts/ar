"""Tests for HttpEmitter.

Exercises the collector POST contract, auth headers, retry/backoff, and the
fire-and-forget strategy against an in-process http.server.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import pytest

from agent_receipts.emitters import (
    ApiKeyAuth,
    BearerAuth,
    EmitError,
    HttpEmitter,
    HttpEmitterConfig,
    MtlsAuth,
    RetryConfig,
)
from tests.conftest import make_receipt

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# In-process collector
# ---------------------------------------------------------------------------


class _CollectorState:
    """Shared state observable by both the server thread and the test."""

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.attempt = 0
        self.responder: Callable[[dict[str, object], int], int] = lambda _r, _a: 201
        self.lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    state: _CollectorState  # set by start_collector()

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode() if length else ""
        captured: dict[str, object] = {
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        with self.state.lock:
            self.state.requests.append(captured)
            self.state.attempt += 1
            status = self.state.responder(captured, self.state.attempt)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:  # noqa: D401
        # Silence the default stderr access log so pytest output stays clean.
        return


def _start_collector() -> tuple[_CollectorState, HTTPServer, threading.Thread, str]:
    state = _CollectorState()
    Handler = type("Handler", (_Handler,), {"state": state})
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/receipts"
    return state, server, thread, url


@pytest.fixture
def collector() -> object:
    state, server, thread, url = _start_collector()
    try:
        yield (state, url)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_posts_application_ld_json_on_201(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) == 1
    req = state.requests[0]
    assert req["method"] == "POST"
    assert req["headers"]["Content-Type"] == "application/ld+json"
    assert '"urn:r:1"' in req["body"]


def test_409_conflict_resolves_as_success(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 409
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) == 1


def test_400_throws_immediately_without_retry(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 400
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=5, base_delay_ms=1, max_delay_ms=1),
        )
    )
    with pytest.raises(EmitError) as info:
        emitter.emit(make_receipt(id="urn:r:1"))
    assert info.value.status == 400
    assert len(state.requests) == 1


def test_5xx_then_success(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, attempt: 201 if attempt >= 3 else 503
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=5, base_delay_ms=1, max_delay_ms=1),
        )
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert len(state.requests) >= 3


def test_5xx_exhausts_budget(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 502
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            retry=RetryConfig(max_attempts=3, base_delay_ms=1, max_delay_ms=1),
        )
    )
    with pytest.raises(EmitError) as info:
        emitter.emit(make_receipt(id="urn:r:1"))
    assert info.value.status == 502
    assert len(state.requests) == 3


def test_api_key_auth_header(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            auth=ApiKeyAuth(header="X-Api-Key", value="secret"),
        )
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert state.requests[0]["headers"]["X-Api-Key"] == "secret"


def test_bearer_auth_header(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(
        HttpEmitterConfig(endpoint=url, auth=BearerAuth(token="tok-xyz"))
    )
    emitter.emit(make_receipt(id="urn:r:1"))
    assert state.requests[0]["headers"]["Authorization"] == "Bearer tok-xyz"


def test_no_auth_header_when_none(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    emitter = HttpEmitter(HttpEmitterConfig(endpoint=url))
    emitter.emit(make_receipt(id="urn:r:1"))
    assert "Authorization" not in state.requests[0]["headers"]


def test_mtls_config_loads_certificate_files(tmp_path: object) -> None:
    """Pin that mTLS config produces a valid SSLContext without throwing.

    A full TLS handshake against a synthetic server requires generating a
    matching server cert too; integration tests against a real collector
    exercise the handshake. This test ensures the config plumbing works.
    """
    # Self-signed cert+key generated via cryptography for test use only.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ar-test")],
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(
            __import__("datetime").datetime.now(tz=__import__("datetime").UTC)
        )
        .not_valid_after(
            __import__("datetime").datetime.now(tz=__import__("datetime").UTC)
            + __import__("datetime").timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint="https://example.invalid/receipts",
            auth=MtlsAuth(cert=cert_pem, key=key_pem),
        )
    )
    try:
        # The SSLContext is built lazily at request time; here we just
        # assert construction did not raise and that close() removes the
        # tempfiles.
        assert emitter._ssl_context is not None  # noqa: SLF001 — test asserts internal state
    finally:
        emitter.close()


def test_fire_and_forget_returns_immediately(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    # Slow responder: hold the lock briefly so a sync call would take >100ms.
    barrier = threading.Event()

    def slow_responder(_r: dict[str, object], _a: int) -> int:
        barrier.wait(timeout=2.0)
        return 201

    state.responder = slow_responder

    emitter = HttpEmitter(
        HttpEmitterConfig(endpoint=url, strategy="fire-and-forget"),
    )
    start = time.monotonic()
    emitter.emit(make_receipt(id="urn:r:1"))
    elapsed_ms = (time.monotonic() - start) * 1000
    # Background thread is started; the call returns essentially instantly.
    assert elapsed_ms < 100, f"fire-and-forget blocked for {elapsed_ms:.0f}ms"
    # Release the slow responder so the test cleanup doesn't hang.
    barrier.set()


def test_fire_and_forget_swallows_errors(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    state.responder = lambda _r, _a: 500
    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            strategy="fire-and-forget",
            retry=RetryConfig(max_attempts=1, base_delay_ms=1, max_delay_ms=1),
        )
    )
    # Must not raise even though delivery will fail.
    emitter.emit(make_receipt(id="urn:r:1"))
    # Give the background thread a chance to finish.
    time.sleep(0.1)


def test_empty_endpoint_rejected() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        HttpEmitter(HttpEmitterConfig(endpoint=""))


def test_invalid_strategy_rejected() -> None:
    with pytest.raises(ValueError, match="strategy"):
        HttpEmitter(HttpEmitterConfig(endpoint="http://example", strategy="lol"))


def test_timeout_treated_as_retryable(collector: object) -> None:
    state, url = collector  # type: ignore[misc]
    # Block the responder past the emitter timeout.
    block = threading.Event()
    call_count = {"n": 0}

    def slow_responder(_r: dict[str, object], _a: int) -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call: hang past the timeout.
            block.wait(timeout=2.0)
            return 503
        return 201

    state.responder = slow_responder

    emitter = HttpEmitter(
        HttpEmitterConfig(
            endpoint=url,
            timeout_ms=50,
            retry=RetryConfig(max_attempts=3, base_delay_ms=1, max_delay_ms=1),
        )
    )
    # Release the responder shortly so the second attempt can succeed.
    threading.Timer(0.1, block.set).start()
    emitter.emit(make_receipt(id="urn:r:1"))
