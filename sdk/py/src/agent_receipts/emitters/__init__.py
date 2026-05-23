"""Emitter abstraction for delivering signed receipts (ADR-0020)."""

from __future__ import annotations

from agent_receipts.emitters.buffering import BufferingEmitter
from agent_receipts.emitters.composite import CompositeEmitter
from agent_receipts.emitters.http import HttpEmitter
from agent_receipts.emitters.in_memory import InMemoryEmitter
from agent_receipts.emitters.types import (
    ApiKeyAuth,
    BearerAuth,
    BufferingFlushError,
    CompositeEmitError,
    EmitError,
    Emitter,
    HttpEmitterAuth,
    HttpEmitterConfig,
    MtlsAuth,
    NoAuth,
    RetryConfig,
)
from agent_receipts.emitters.wal import (
    FileWal,
    MemoryWal,
    Wal,
    WalDrainResult,
    WalEmitter,
)

__all__ = [
    "ApiKeyAuth",
    "BearerAuth",
    "BufferingEmitter",
    "BufferingFlushError",
    "CompositeEmitError",
    "CompositeEmitter",
    "EmitError",
    "Emitter",
    "FileWal",
    "HttpEmitter",
    "HttpEmitterAuth",
    "HttpEmitterConfig",
    "InMemoryEmitter",
    "MemoryWal",
    "MtlsAuth",
    "NoAuth",
    "RetryConfig",
    "Wal",
    "WalDrainResult",
    "WalEmitter",
]
