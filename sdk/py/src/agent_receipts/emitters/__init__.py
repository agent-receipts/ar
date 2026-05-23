"""Emitter abstraction for delivering signed receipts (ADR-0020)."""

from __future__ import annotations

from agent_receipts.emitters.buffering import BufferingEmitter
from agent_receipts.emitters.composite import CompositeEmitter
from agent_receipts.emitters.http import HttpEmitter
from agent_receipts.emitters.in_memory import InMemoryEmitter
from agent_receipts.emitters.types import (
    ApiKeyAuth,
    BearerAuth,
    CompositeEmitError,
    EmitError,
    Emitter,
    HttpEmitterAuth,
    HttpEmitterConfig,
    MtlsAuth,
    NoAuth,
    RetryConfig,
)

__all__ = [
    "ApiKeyAuth",
    "BearerAuth",
    "BufferingEmitter",
    "CompositeEmitError",
    "CompositeEmitter",
    "EmitError",
    "Emitter",
    "HttpEmitter",
    "HttpEmitterAuth",
    "HttpEmitterConfig",
    "InMemoryEmitter",
    "MtlsAuth",
    "NoAuth",
    "RetryConfig",
]
