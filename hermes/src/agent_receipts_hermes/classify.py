"""Classify hermes-agent tool calls into Agent Receipts action types.

Lookup order:
    1. Exact ``tool_name`` match against the loaded mappings.
    2. First ``prefix`` pattern whose prefix matches the tool name.
    3. Fall back to ``UNKNOWN_ACTION`` (sdk-py default).

Custom taxonomies merge with the bundled defaults: custom mappings
override built-ins by ``tool_name``; custom patterns override built-ins
by ``prefix``. Custom-first ordering matches the openclaw plugin so the
two implementations stay observationally consistent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from agent_receipts.taxonomy.actions import (
    UNKNOWN_ACTION,
    get_action_type,
    resolve_action_type,
)


@dataclass(frozen=True)
class TaxonomyMapping:
    """Exact tool-name → action-type mapping with optional disclosure hints."""

    tool_name: str
    action_type: str
    disclosure_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaxonomyPattern:
    """Prefix-based fallback mapping used when no exact mapping matches."""

    prefix: str
    action_type: str


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a hermes tool call."""

    action_type: str
    risk_level: str
    disclosure_fields: tuple[str, ...] = ()


def _load_default_taxonomy() -> tuple[list[TaxonomyMapping], list[TaxonomyPattern]]:
    package = __package__
    if not package:  # pragma: no cover - module is never imported standalone
        msg = "agent_receipts_hermes must be imported as a package"
        raise RuntimeError(msg)
    raw = files(package).joinpath("taxonomy.json").read_text(encoding="utf-8")
    return _parse_taxonomy_payload(raw)


def _parse_taxonomy_payload(
    raw: str,
) -> tuple[list[TaxonomyMapping], list[TaxonomyPattern]]:
    parsed: object = json.loads(raw)
    if not isinstance(parsed, dict):
        msg = 'Invalid taxonomy file: expected { "mappings": [...], "patterns": [...] }'
        raise ValueError(msg)
    parsed_dict = cast("dict[str, Any]", parsed)

    mappings = _parse_mappings(parsed_dict.get("mappings", []))
    patterns = _parse_patterns(parsed_dict.get("patterns", []))
    return mappings, patterns


def _parse_mappings(raw: object) -> list[TaxonomyMapping]:
    if not isinstance(raw, list):
        raise ValueError('Invalid taxonomy: "mappings" must be a list')
    raw_list = cast("list[Any]", raw)

    seen: set[str] = set()
    result: list[TaxonomyMapping] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            raise ValueError(
                "Invalid taxonomy mapping: each entry must be an object with"
                ' "tool_name" and "action_type" string fields'
            )
        entry_dict = cast("dict[str, Any]", entry)
        tool_name: object = entry_dict.get("tool_name")
        action_type: object = entry_dict.get("action_type")
        disclosure: object = entry_dict.get("disclosure_fields", [])

        if (
            not isinstance(tool_name, str)
            or not isinstance(action_type, str)
            or not tool_name
            or not action_type
        ):
            raise ValueError(
                'Invalid taxonomy mapping: "tool_name" and "action_type" must be'
                " non-empty strings"
            )
        if get_action_type(action_type) is None:
            raise ValueError(
                f'Unknown action_type "{action_type}" for tool_name "{tool_name}"'
            )
        if tool_name in seen:
            raise ValueError(f'Duplicate taxonomy mapping for tool_name "{tool_name}"')
        seen.add(tool_name)

        fields: tuple[str, ...] = ()
        if disclosure:
            if not isinstance(disclosure, list):
                raise ValueError(
                    f'Invalid disclosure_fields for "{tool_name}": expected a list'
                )
            disclosure_list = cast("list[Any]", disclosure)
            checked: list[str] = []
            for field in disclosure_list:
                if not isinstance(field, str) or not field:
                    raise ValueError(
                        f'Invalid disclosure_fields for "{tool_name}": entries'
                        " must be non-empty strings"
                    )
                checked.append(field)
            fields = tuple(checked)

        result.append(
            TaxonomyMapping(
                tool_name=tool_name,
                action_type=action_type,
                disclosure_fields=fields,
            )
        )
    return result


def _parse_patterns(raw: object) -> list[TaxonomyPattern]:
    if not isinstance(raw, list):
        raise ValueError('Invalid taxonomy: "patterns" must be a list')
    raw_list = cast("list[Any]", raw)

    result: list[TaxonomyPattern] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            raise ValueError(
                "Invalid taxonomy pattern: each entry must be an object with"
                ' "prefix" and "action_type" string fields'
            )
        entry_dict = cast("dict[str, Any]", entry)
        prefix: object = entry_dict.get("prefix")
        action_type: object = entry_dict.get("action_type")
        if (
            not isinstance(prefix, str)
            or not isinstance(action_type, str)
            or not prefix
            or not action_type
        ):
            raise ValueError(
                'Invalid taxonomy pattern: "prefix" and "action_type" must be'
                " non-empty strings"
            )
        if get_action_type(action_type) is None:
            raise ValueError(
                f'Unknown action_type "{action_type}" for prefix "{prefix}"'
            )
        result.append(TaxonomyPattern(prefix=prefix, action_type=action_type))
    return result


_DEFAULTS = _load_default_taxonomy()
DEFAULT_MAPPINGS: list[TaxonomyMapping] = _DEFAULTS[0]
DEFAULT_PATTERNS: list[TaxonomyPattern] = _DEFAULTS[1]


def load_custom_taxonomy(
    file_path: str | Path,
) -> tuple[list[TaxonomyMapping], list[TaxonomyPattern]]:
    """Merge a user-supplied taxonomy file with the bundled defaults.

    The returned lists are custom-first: matches scan custom entries before
    falling back to defaults, mirroring the openclaw plugin.
    """
    raw = Path(file_path).read_text(encoding="utf-8")
    custom_mappings, custom_patterns = _parse_taxonomy_payload(raw)

    custom_names = {m.tool_name for m in custom_mappings}
    merged_mappings: list[TaxonomyMapping] = [
        *custom_mappings,
        *(m for m in DEFAULT_MAPPINGS if m.tool_name not in custom_names),
    ]

    custom_prefixes = {p.prefix for p in custom_patterns}
    merged_patterns: list[TaxonomyPattern] = [
        *custom_patterns,
        *(p for p in DEFAULT_PATTERNS if p.prefix not in custom_prefixes),
    ]

    return merged_mappings, merged_patterns


def classify(
    tool_name: str,
    mappings: list[TaxonomyMapping] | None = None,
    patterns: list[TaxonomyPattern] | None = None,
) -> ClassificationResult:
    """Classify a hermes tool call into an Agent Receipts action type.

    Exact-match first, then prefix patterns, then ``UNKNOWN_ACTION``.
    """
    effective_mappings = mappings if mappings is not None else DEFAULT_MAPPINGS
    effective_patterns = patterns if patterns is not None else DEFAULT_PATTERNS

    exact = next((m for m in effective_mappings if m.tool_name == tool_name), None)
    if exact is not None:
        entry = resolve_action_type(exact.action_type)
        return ClassificationResult(
            action_type=entry.type,
            risk_level=entry.risk_level,
            disclosure_fields=exact.disclosure_fields,
        )

    for pattern in effective_patterns:
        if tool_name.startswith(pattern.prefix):
            entry = resolve_action_type(pattern.action_type)
            return ClassificationResult(
                action_type=entry.type,
                risk_level=entry.risk_level,
            )

    return ClassificationResult(
        action_type=UNKNOWN_ACTION.type,
        risk_level=UNKNOWN_ACTION.risk_level,
    )
