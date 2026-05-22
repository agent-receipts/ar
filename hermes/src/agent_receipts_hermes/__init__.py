"""agent_receipts_hermes — Agent Receipts plugin for hermes-agent.

Activation is handled by the hermes plugin system. At runtime hermes calls
:func:`register` with a context object exposing
``ctx.register_hook(name, callback)``. We attach ``pre_tool_call`` and
``post_tool_call`` handlers that classify every tool invocation and
forward a frame to the local agent-receipts daemon over its AF_UNIX
socket. The daemon signs, hash-links, and persists each receipt.

The plugin also exposes two agent-callable tools — ``ar_query_receipts``
and ``ar_verify_chain`` — registered through whichever method the host
``ctx`` exposes (best-effort across hermes versions).

Per ADR-0010 (Flavor B) the plugin holds NO crypto material and NO chain
state. The daemon is the single source of truth; if the socket is
unreachable, frames drop fire-and-forget and a one-shot warning is
logged at startup.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from agent_receipts.emitter import Emitter

from agent_receipts_hermes._version import VERSION
from agent_receipts_hermes.classify import (
    DEFAULT_MAPPINGS,
    DEFAULT_PATTERNS,
    ClassificationResult,
    TaxonomyMapping,
    TaxonomyPattern,
    classify,
    load_custom_taxonomy,
)
from agent_receipts_hermes.config import (
    PluginConfig,
    default_daemon_db_path,
    default_daemon_public_key_path,
    default_socket_path,
    resolve_config,
)
from agent_receipts_hermes.hooks import (
    HookState,
    post_tool_call,
    pre_tool_call,
)
from agent_receipts_hermes.tools import (
    ToolDeps,
    ToolSpec,
    build_tools,
)

logger = logging.getLogger(__name__)

__all__ = [
    "VERSION",
    "ClassificationResult",
    "HookState",
    "PluginConfig",
    "TaxonomyMapping",
    "TaxonomyPattern",
    "ToolDeps",
    "ToolSpec",
    "build_tools",
    "classify",
    "default_daemon_db_path",
    "default_daemon_public_key_path",
    "default_socket_path",
    "load_custom_taxonomy",
    "post_tool_call",
    "pre_tool_call",
    "register",
    "resolve_config",
]


def _attempt_register_tool(ctx: Any, tool: ToolSpec) -> bool:
    """Best-effort tool registration across hermes API surfaces.

    The public hermes docs only describe ``ctx.register_hook``. To stay
    forwards-compatible we probe a handful of plausible registration
    method names and shapes, returning ``True`` on the first one that
    accepts our call. If none match we log a warning so operators know
    the introspection tools are not wired up — the receipt-forwarding
    hooks (the real value) work either way.
    """
    candidates: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = [
        (
            "register_tool",
            (),
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
                "execute": tool.execute,
            },
        ),
        (
            "register_tool",
            (tool.name, tool.parameters, tool.execute),
            {"description": tool.description},
        ),
        ("register_tool", (tool.name, tool.execute), {}),
        (
            "add_tool",
            (),
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
                "execute": tool.execute,
            },
        ),
    ]

    for method_name, args, kwargs in candidates:
        method = getattr(ctx, method_name, None)
        if not callable(method):
            continue
        try:
            method(*args, **kwargs)
            return True
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "agent-receipts: ctx.%s raised registering %s: %s",
                method_name,
                tool.name,
                exc,
            )
            return False
    return False


def register(ctx: Any) -> HookState:
    """Wire the plugin into a hermes-agent runtime.

    Returns the per-instance :class:`HookState` so tests can inspect the
    pending map / mappings / emitter directly. Runtime callers normally
    ignore the return value.
    """
    raw_cfg: Any = getattr(ctx, "plugin_config", None)
    if raw_cfg is None:
        raw_cfg = getattr(ctx, "config", None)
    cfg_dict: dict[str, Any] | None = (
        cast("dict[str, Any]", raw_cfg) if isinstance(raw_cfg, dict) else None
    )
    cfg = resolve_config(cfg_dict)

    if not cfg.enabled:
        logger.info("agent-receipts: plugin disabled via config")
        return HookState(emitter=None)

    if cfg.deprecated_keys:
        logger.warning(
            "agent-receipts: deprecated config keys ignored: %s",
            ", ".join(cfg.deprecated_keys),
        )

    mappings: list[TaxonomyMapping] = list(DEFAULT_MAPPINGS)
    patterns: list[TaxonomyPattern] = list(DEFAULT_PATTERNS)
    if cfg.taxonomy_path:
        try:
            mappings, patterns = load_custom_taxonomy(cfg.taxonomy_path)
            logger.info(
                "agent-receipts: loaded custom taxonomy from %s", cfg.taxonomy_path
            )
        except (OSError, ValueError) as exc:
            logger.warning(
                "agent-receipts: failed to load taxonomy %s: %s — using defaults",
                cfg.taxonomy_path,
                exc,
            )

    emitter: Emitter | None = None
    if cfg.socket_path:
        try:
            emitter = Emitter(socket_path=cfg.socket_path)
        except ValueError as exc:
            logger.warning("agent-receipts: emitter construction failed: %s", exc)
    else:
        logger.warning(
            "agent-receipts: no default socket path on this platform; "
            "set AGENTRECEIPTS_SOCKET. Tool calls will not be recorded."
        )

    state = HookState(
        channel=cfg.channel,
        mappings=mappings,
        patterns=patterns,
        emitter=emitter,
    )

    register_hook = getattr(ctx, "register_hook", None)
    if not callable(register_hook):
        logger.warning(
            "agent-receipts: ctx.register_hook is not callable; "
            "no tool calls will be recorded."
        )
        return state

    def _pre(**kwargs: Any) -> None:
        pre_tool_call(state, **kwargs)

    def _post(**kwargs: Any) -> None:
        post_tool_call(state, **kwargs)

    register_hook("pre_tool_call", _pre)
    register_hook("post_tool_call", _post)

    tool_deps = ToolDeps(
        daemon_db_path=cfg.daemon_db_path,
        daemon_public_key_path=cfg.daemon_public_key_path,
    )
    registered: list[str] = []
    skipped: list[str] = []
    for tool in build_tools(tool_deps):
        if _attempt_register_tool(ctx, tool):
            registered.append(tool.name)
        else:
            skipped.append(tool.name)

    if skipped:
        logger.warning(
            "agent-receipts: could not register tools via ctx (%s); the hooks "
            "still record receipts, but agents will not see %s.",
            ", ".join(skipped),
            " / ".join(skipped),
        )

    logger.info(
        "agent-receipts: hermes plugin v%s ready — socket=%s, db=%s, tools=%s",
        VERSION,
        cfg.socket_path or "<none>",
        cfg.daemon_db_path,
        registered or "none",
    )
    return state
