"""HttpEmitter — POSTs signed receipts to a collector endpoint (ADR-0020).

Wire contract (per ADR-0020 §"Collector contract"):

    POST <endpoint>
    Content-Type: application/ld+json
    Body: JSON-serialised AgentReceipt

    201 Created    -> resolve
    409 Conflict   -> resolve (duplicate id is idempotent re-delivery)
    400 Bad Request-> raise EmitError immediately (no retry)
    5xx / network  -> retry with exponential backoff + jitter

Strategy:
    - "sync" (default): emit() waits for the collector ack and respects
      the full retry budget.
    - "fire-and-forget": emit() schedules the POST on a background
      thread and returns immediately; the background thread's error is
      logged at debug and never raised to the caller.

mTLS support uses :func:`ssl.SSLContext.load_cert_chain` which requires
file paths. The PEM-encoded bytes are written to a per-instance
:class:`tempfile.NamedTemporaryFile` at construction; the files live as
long as the emitter does and are cleaned up on close.
"""

from __future__ import annotations

import logging
import os
import random
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

from agent_receipts.emitters.types import (
    ApiKeyAuth,
    BearerAuth,
    EmitError,
    HttpEmitterConfig,
    MtlsAuth,
    NoAuth,
    RetryConfig,
)

if TYPE_CHECKING:
    from agent_receipts.receipt.types import AgentReceipt

logger = logging.getLogger(__name__)


class HttpEmitter:
    """POSTs signed receipts to a collector endpoint over HTTP(S)."""

    def __init__(self, config: HttpEmitterConfig) -> None:
        if not config.endpoint:
            raise ValueError("HttpEmitter: endpoint is required")
        self._endpoint = config.endpoint
        self._auth = config.auth
        self._strategy = config.strategy
        if self._strategy not in ("sync", "fire-and-forget"):
            raise ValueError(
                f"HttpEmitter: invalid strategy {config.strategy!r} "
                "(want 'sync' or 'fire-and-forget')"
            )
        self._retry = config.retry
        self._timeout = config.timeout_ms / 1000.0

        # mTLS bytes -> on-disk PEM files -> SSLContext. We keep the
        # tempfiles alive for the emitter's lifetime so the SSL handshake
        # can load them on every request.
        self._mtls_cert_file: str | None = None
        self._mtls_key_file: str | None = None
        self._ssl_context: ssl.SSLContext | None = None
        if isinstance(self._auth, MtlsAuth):
            cert_path, key_path = _write_mtls_files(self._auth.cert, self._auth.key)
            self._mtls_cert_file = cert_path
            self._mtls_key_file = key_path
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self._ssl_context = ctx

    def emit(self, receipt: AgentReceipt) -> None:
        body = receipt.model_dump_json(by_alias=True).encode()

        if self._strategy == "fire-and-forget":
            # Schedule on a daemon thread so the worker doesn't keep the
            # interpreter alive past the caller's exit. Errors are
            # swallowed because the caller explicitly opted in to no
            # guarantee.
            threading.Thread(
                target=self._fire_and_forget,
                args=(body,),
                daemon=True,
            ).start()
            return

        self._deliver(body)

    def close(self) -> None:
        """Release the mTLS temp files, if any. Safe to call multiple times."""
        for path in (self._mtls_cert_file, self._mtls_key_file):
            if path is None:
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
        self._mtls_cert_file = None
        self._mtls_key_file = None

    # Allow `with HttpEmitter(...) as e:` for clean cleanup in tests.
    def __enter__(self) -> HttpEmitter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------

    def _fire_and_forget(self, body: bytes) -> None:
        try:
            self._deliver(body)
        except Exception as exc:  # noqa: BLE001 — fire-and-forget swallows everything
            logger.debug(
                "HttpEmitter dropped receipt (fire-and-forget)",
                extra={"endpoint": self._endpoint, "err": str(exc)},
            )

    def _deliver(self, body: bytes) -> None:
        last_error: BaseException | None = None
        last_status: int | None = None

        for attempt in range(1, self._retry.max_attempts + 1):
            try:
                status = self._do_request(body)
            except urllib.error.HTTPError as exc:
                # urllib raises HTTPError for any non-2xx; treat it as a
                # transport-level result so we can apply the status-mapping
                # logic uniformly.
                status = exc.code
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                last_status = None
                if attempt >= self._retry.max_attempts:
                    break
                time.sleep(_backoff_delay(self._retry, attempt) / 1000.0)
                continue

            if status in (201, 409):
                return
            if status == 400:
                raise EmitError(
                    f"HttpEmitter: 400 Bad Request from {self._endpoint}",
                    status=400,
                )
            if 500 <= status < 600:
                last_error = EmitError(
                    f"HttpEmitter: HTTP {status} from {self._endpoint}",
                    status=status,
                )
                last_status = status
                if attempt >= self._retry.max_attempts:
                    break
                time.sleep(_backoff_delay(self._retry, attempt) / 1000.0)
                continue
            # Any other status (401/403/404/4xx) is non-retryable.
            raise EmitError(
                f"HttpEmitter: unexpected HTTP {status} from {self._endpoint}",
                status=status,
            )

        raise EmitError(
            f"HttpEmitter: {self._retry.max_attempts} attempts exhausted for "
            f"{self._endpoint}",
            status=last_status,
        ) from last_error

    def _do_request(self, body: bytes) -> int:
        headers: dict[str, str] = {"Content-Type": "application/ld+json"}
        if isinstance(self._auth, ApiKeyAuth):
            headers[self._auth.header] = self._auth.value
        elif isinstance(self._auth, BearerAuth):
            headers["Authorization"] = f"Bearer {self._auth.token}"
        # NoAuth and MtlsAuth contribute no headers; mTLS goes via SSLContext.

        req = urllib.request.Request(  # noqa: S310 — endpoint is caller-controlled, by design
            self._endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        open_kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._ssl_context is not None:
            open_kwargs["context"] = self._ssl_context

        with urllib.request.urlopen(req, **open_kwargs) as resp:  # noqa: S310 — same justification
            return int(resp.status)


def _backoff_delay(retry: RetryConfig, attempt: int) -> int:
    """Exponential backoff with full jitter, capped at max_delay_ms."""
    exp = min(retry.max_delay_ms, retry.base_delay_ms * (2 ** (attempt - 1)))
    return random.randint(0, exp)  # noqa: S311 — jitter, not crypto


def _write_mtls_files(cert: bytes, key: bytes) -> tuple[str, str]:
    """Write PEM cert+key to per-instance tempfiles. Returns (cert_path, key_path).

    Python's SSLContext.load_cert_chain requires file paths up through
    3.12; in-memory loading was added in 3.13. We target 3.11+ so the
    tempfile path is required.
    """
    cert_fd, cert_path = tempfile.mkstemp(prefix="ar-mtls-cert-", suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(prefix="ar-mtls-key-", suffix=".pem")
    try:
        os.write(cert_fd, cert)
        os.write(key_fd, key)
    finally:
        os.close(cert_fd)
        os.close(key_fd)
    # Tighten permissions on the private key — tempfile already opens at
    # 0600 on POSIX, but be explicit so reviewers don't have to check.
    os.chmod(key_path, 0o600)
    return cert_path, key_path


# Convenience re-exports so callers can do `from agent_receipts.emitters
# import NoAuth` without pulling from a deeply nested module.
__all__ = [
    "ApiKeyAuth",
    "BearerAuth",
    "EmitError",
    "HttpEmitter",
    "HttpEmitterConfig",
    "MtlsAuth",
    "NoAuth",
    "RetryConfig",
]
