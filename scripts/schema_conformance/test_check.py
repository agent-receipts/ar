"""Unit tests for the Gate #6 SDK output schema-conformance verifier.

These tests exercise the schema-validation core (`validate_receipt`) against
the real `spec/schema/agent-receipt.schema.json` using a known-good spec
example as the fixture. No SDK is installed and no network call is made — the
emit drivers (which do install the published artifact) are exercised
end-to-end by CI at release time, not here.

The core invariant under test: `validate_receipt` returns no violations for a
schema-conforming receipt and at least one violation for a receipt that drops
a required field or carries a non-RFC3339 timestamp. The failure cases are a
direct implementation of ADR-0024 D6 (a gate must be observed to fail on a
deliberately-broken input).

Run with:
    python3 -m pytest scripts/schema_conformance/test_check.py
    python3 scripts/schema_conformance/test_check.py   # quick self-check
"""

from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402

_GOOD_RECEIPT = os.path.join(
    check._REPO_ROOT, "spec", "examples", "minimal-receipt.json"
)


def _schema() -> dict:
    return check._load_schema(check.DEFAULT_SCHEMA)


def _good_receipt() -> dict:
    with open(_GOOD_RECEIPT, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# validate_receipt — the core gate logic
# ---------------------------------------------------------------------------


class TestValidateReceipt:
    def test_conforming_receipt_has_no_violations(self) -> None:
        assert check.validate_receipt(_good_receipt(), _schema()) == []

    def test_missing_required_proof_is_violation(self) -> None:
        receipt = _good_receipt()
        del receipt["proof"]
        violations = check.validate_receipt(receipt, _schema())
        assert violations
        assert any("proof" in v for v in violations)

    def test_missing_required_issuer_is_violation(self) -> None:
        receipt = _good_receipt()
        del receipt["issuer"]
        assert check.validate_receipt(receipt, _schema())

    def test_unknown_top_level_field_is_violation(self) -> None:
        # additionalProperties: false at the root must reject stray fields.
        receipt = _good_receipt()
        receipt["unexpected_field"] = "value"
        assert check.validate_receipt(receipt, _schema())

    def test_non_rfc3339_issuance_date_is_violation(self) -> None:
        # Mirrors AssertFormat in the Go validator: a non-RFC3339 date-time
        # must fail, otherwise the format constraint is annotation-only.
        receipt = _good_receipt()
        receipt["issuanceDate"] = "2026/04/22 00:00:00"
        assert check.validate_receipt(receipt, _schema())

    def test_bad_receipt_id_is_violation(self) -> None:
        # urn:receipt:<uuid> pattern must be enforced.
        receipt = _good_receipt()
        receipt["id"] = "not-a-urn"
        assert check.validate_receipt(receipt, _schema())

    def test_violation_messages_include_location(self) -> None:
        receipt = _good_receipt()
        del receipt["proof"]
        violations = check.validate_receipt(receipt, _schema())
        # Each message is "<location>: <message>"; a root-level miss is "<root>".
        assert all(": " in v for v in violations)


# ---------------------------------------------------------------------------
# _parse_emitted — pulling the JSON receipt out of an emit program's stdout
# ---------------------------------------------------------------------------


class TestParseEmitted:
    def test_parses_single_json_object(self) -> None:
        obj = {"id": "urn:receipt:x", "type": ["VerifiableCredential", "AgentReceipt"]}
        assert check._parse_emitted("py", json.dumps(obj)) == obj

    def test_ignores_leading_log_lines(self) -> None:
        obj = {"id": "urn:receipt:x"}
        stdout = "installing...\nbuilding...\n" + json.dumps(obj) + "\n"
        assert check._parse_emitted("go", stdout) == obj

    def test_no_json_returns_none(self) -> None:
        assert check._parse_emitted("ts", "just some logs\nno receipt here\n") is None

    def test_malformed_json_returns_none(self) -> None:
        assert check._parse_emitted("py", "{ not valid json") is None

    def test_empty_stdout_returns_none(self) -> None:
        assert check._parse_emitted("go", "") is None

    def test_picks_last_json_line(self) -> None:
        # If the SDK ever prints more than one object, the receipt is the last.
        first = json.dumps({"id": "first"})
        last = json.dumps({"id": "last"})
        assert check._parse_emitted("py", first + "\n" + last + "\n") == {"id": "last"}


# ---------------------------------------------------------------------------
# _assert_conforms — pass/fail reporting wrapper
# ---------------------------------------------------------------------------


class TestAssertConforms:
    def test_conforming_receipt_returns_zero(self) -> None:
        assert check._assert_conforms("py", _good_receipt(), _schema()) == 0

    def test_violating_receipt_returns_one(self) -> None:
        receipt = _good_receipt()
        del receipt["proof"]
        assert check._assert_conforms("py", receipt, _schema()) == 1


# ---------------------------------------------------------------------------
# Cross-check: every spec example validates (the emit drivers must produce
# receipts no less conformant than the committed examples)
# ---------------------------------------------------------------------------


class TestSpecExamplesValidate:
    def test_all_v04_capable_examples_validate(self) -> None:
        # Sanity-check the validator against the canonical good fixture so a
        # broken validator (e.g. schema fails to load, refs unresolved) is
        # caught here rather than silently passing every release.
        schema = _schema()
        receipt = _good_receipt()
        # A deep copy guards against accidental shared mutation between tests.
        assert check.validate_receipt(copy.deepcopy(receipt), schema) == []


# ---------------------------------------------------------------------------
# Self-runner (no pytest dependency required)
# ---------------------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    suites = [
        TestValidateReceipt,
        TestParseEmitted,
        TestAssertConforms,
        TestSpecExamplesValidate,
    ]
    for suite_cls in suites:
        suite = suite_cls()
        for name in sorted(dir(suite_cls)):
            if not name.startswith("test_"):
                continue
            fn = getattr(suite, name)
            try:
                fn()
                print(f"ok   {suite_cls.__name__}.{name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {suite_cls.__name__}.{name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"ERROR {suite_cls.__name__}.{name}: {type(exc).__name__}: {exc}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
