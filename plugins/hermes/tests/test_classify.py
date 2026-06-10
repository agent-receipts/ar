"""Taxonomy classification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_receipts_hermes.classify import (
    DEFAULT_MAPPINGS,
    DEFAULT_PATTERNS,
    TaxonomyMapping,
    TaxonomyPattern,
    classify,
    load_custom_taxonomy,
)


class TestClassifyExactMatch:
    def test_known_filesystem_tool_returns_filesystem_action(self) -> None:
        result = classify("read_file")
        assert result.action_type == "filesystem.file.read"
        assert result.risk_level == "low"
        assert "path" in result.disclosure_fields

    def test_known_command_tool_marked_high_risk(self) -> None:
        result = classify("bash")
        assert result.action_type == "system.command.execute"
        assert result.risk_level == "high"

    def test_unknown_tool_falls_back_to_unknown(self) -> None:
        result = classify("definitely_not_a_real_tool_name_42")
        assert result.action_type == "unknown"
        assert result.disclosure_fields == ()


class TestClassifyPrefixPattern:
    def test_browser_prefix_matches_when_no_exact_mapping(self) -> None:
        result = classify("browser_press_key")
        assert result.action_type == "system.browser.navigate"

    def test_exact_mapping_wins_over_prefix(self) -> None:
        # "browser_click" has both an exact mapping (form_submit) and would
        # match the "browser_" prefix (navigate). Exact mapping must win.
        result = classify("browser_click")
        assert result.action_type == "system.browser.form_submit"

    def test_no_pattern_match_falls_back_to_unknown(self) -> None:
        result = classify("zzz_no_prefix_match")
        assert result.action_type == "unknown"


class TestCustomTaxonomy:
    def test_custom_mapping_overrides_default(self, tmp_path: Path) -> None:
        # "read_file" defaults to filesystem.file.read; we re-classify it
        # as filesystem.file.modify to confirm custom-first ordering.
        custom = tmp_path / "taxonomy.json"
        custom.write_text(
            json.dumps(
                {
                    "mappings": [
                        {
                            "tool_name": "read_file",
                            "action_type": "filesystem.file.modify",
                            "disclosure_fields": ["override"],
                        }
                    ],
                    "patterns": [],
                }
            )
        )

        mappings, patterns = load_custom_taxonomy(custom)
        result = classify("read_file", mappings, patterns)
        assert result.action_type == "filesystem.file.modify"
        assert result.disclosure_fields == ("override",)

    def test_custom_pattern_overrides_default(self, tmp_path: Path) -> None:
        custom = tmp_path / "taxonomy.json"
        custom.write_text(
            json.dumps(
                {
                    "mappings": [],
                    "patterns": [
                        {"prefix": "browser_", "action_type": "system.command.execute"}
                    ],
                }
            )
        )

        mappings, patterns = load_custom_taxonomy(custom)
        result = classify("browser_unknown_action", mappings, patterns)
        assert result.action_type == "system.command.execute"

    def test_default_mapping_preserved_when_custom_only_adds_new(
        self, tmp_path: Path
    ) -> None:
        custom = tmp_path / "taxonomy.json"
        custom.write_text(
            json.dumps(
                {
                    "mappings": [
                        {
                            "tool_name": "my_brand_new_tool",
                            "action_type": "filesystem.file.read",
                        }
                    ],
                    "patterns": [],
                }
            )
        )

        mappings, _ = load_custom_taxonomy(custom)
        # New tool present and old tools still classified normally.
        assert any(m.tool_name == "my_brand_new_tool" for m in mappings)
        assert any(m.tool_name == "read_file" for m in mappings)

    def test_unknown_action_type_in_custom_raises(self, tmp_path: Path) -> None:
        custom = tmp_path / "taxonomy.json"
        custom.write_text(
            json.dumps(
                {
                    "mappings": [
                        {"tool_name": "x", "action_type": "not.a.real.action.type"}
                    ],
                    "patterns": [],
                }
            )
        )
        with pytest.raises(ValueError, match="Unknown action_type"):
            load_custom_taxonomy(custom)

    def test_duplicate_tool_name_in_custom_raises(self, tmp_path: Path) -> None:
        custom = tmp_path / "taxonomy.json"
        custom.write_text(
            json.dumps(
                {
                    "mappings": [
                        {"tool_name": "x", "action_type": "filesystem.file.read"},
                        {"tool_name": "x", "action_type": "filesystem.file.read"},
                    ],
                    "patterns": [],
                }
            )
        )
        with pytest.raises(ValueError, match="Duplicate"):
            load_custom_taxonomy(custom)


class TestDefaultTaxonomy:
    def test_defaults_loaded_without_errors(self) -> None:
        assert DEFAULT_MAPPINGS, "bundled taxonomy must yield at least one mapping"
        assert DEFAULT_PATTERNS, "bundled taxonomy must yield at least one pattern"

    def test_every_mapping_is_well_formed(self) -> None:
        for mapping in DEFAULT_MAPPINGS:
            assert isinstance(mapping, TaxonomyMapping)
            assert mapping.tool_name
            assert mapping.action_type

    def test_every_pattern_is_well_formed(self) -> None:
        for pattern in DEFAULT_PATTERNS:
            assert isinstance(pattern, TaxonomyPattern)
            assert pattern.prefix
            assert pattern.action_type
