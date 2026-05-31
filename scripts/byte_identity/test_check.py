"""Unit tests for the Gate #7 cross-SDK byte-identity verifier.

These tests exercise the comparison core (`compare_actuals` and its
`SAME_AS_`/skip resolution) against the real
`cross-sdk-tests/canonicalization_vectors.json`. No SDK is installed and no
network call is made — the drivers (which install the published artifact and
run the vectors through it) are exercised end-to-end by CI at release time, not
here.

The core invariant under test: `compare_actuals` returns no divergences when an
SDK reproduces every committed `canonical` byte and every pinned receipt hash,
and at least one divergence when any output drifts — a flipped canonical byte,
a mismatched receipt hash, a broken `SAME_AS_` invariant, or a missing output.
The failure cases are a direct implementation of ADR-0024 D6 (a gate must be
observed to fail on a deliberately-broken input).

Run with:
    python3 -m pytest scripts/byte_identity/test_check.py
    python3 scripts/byte_identity/test_check.py   # quick self-check
"""

from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402


def _vectors() -> dict:
    return check._load_vectors(check.DEFAULT_VECTORS)


def _faithful_actuals(vectors: dict) -> dict:
    """Build the output a perfectly byte-identical SDK would emit.

    `canonical` echoes each committed `canonical` string. `receipt_hash` echoes
    each vector's resolved expected hash, so a faithful SDK passes and any
    mutation a test makes is the only source of divergence.
    """
    canonical = {
        v["name"]: v["canonical"] for v in vectors["canonicalization_vectors"]
    }
    receipt_hash = dict(check._resolve_receipt_hashes(vectors["receipt_hash_vectors"]))
    return {"canonical": canonical, "receipt_hash": receipt_hash}


# ---------------------------------------------------------------------------
# compare_actuals — the core gate logic
# ---------------------------------------------------------------------------


class TestCompareActuals:
    def test_faithful_output_has_no_divergence(self) -> None:
        vectors = _vectors()
        assert check.compare_actuals(vectors, _faithful_actuals(vectors)) == []

    def test_flipped_canonical_byte_is_divergence(self) -> None:
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        # Mutate one vector's canonical output by a single byte.
        name = vectors["canonicalization_vectors"][2]["name"]
        actuals["canonical"][name] = actuals["canonical"][name] + " "
        diffs = check.compare_actuals(vectors, actuals)
        assert diffs
        assert any(name in d and "canonical bytes diverge" in d for d in diffs)

    def test_missing_canonical_output_is_divergence(self) -> None:
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        name = vectors["canonicalization_vectors"][0]["name"]
        del actuals["canonical"][name]
        diffs = check.compare_actuals(vectors, actuals)
        assert any(name in d and "no output" in d for d in diffs)

    def test_correct_bytes_wrong_pinned_hash_is_divergence(self) -> None:
        # A vector that pins an expectedHash: the canonical bytes are right but
        # the gate also recomputes the SHA-256. Corrupt the committed hash and
        # confirm the recompute catches it (guards a hash-encoding regression).
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        hashed = next(
            v for v in vectors["canonicalization_vectors"] if v.get("expectedHash")
        )
        vectors = copy.deepcopy(vectors)
        for v in vectors["canonicalization_vectors"]:
            if v["name"] == hashed["name"]:
                v["expectedHash"] = "sha256:" + "0" * 64
        diffs = check.compare_actuals(vectors, actuals)
        assert any(hashed["name"] in d and "SHA-256 diverges" in d for d in diffs)

    def test_mismatched_receipt_hash_is_divergence(self) -> None:
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        name = next(iter(actuals["receipt_hash"]))
        actuals["receipt_hash"][name] = "sha256:" + "0" * 64
        diffs = check.compare_actuals(vectors, actuals)
        assert any(name in d and "receipt hash diverges" in d for d in diffs)

    def test_missing_receipt_hash_output_is_divergence(self) -> None:
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        name = next(iter(actuals["receipt_hash"]))
        del actuals["receipt_hash"][name]
        diffs = check.compare_actuals(vectors, actuals)
        assert any(name in d and "no output" in d for d in diffs)

    def test_divergence_messages_show_got_and_want(self) -> None:
        vectors = _vectors()
        actuals = _faithful_actuals(vectors)
        name = vectors["canonicalization_vectors"][1]["name"]
        actuals["canonical"][name] = "WRONG"
        diffs = check.compare_actuals(vectors, actuals)
        assert any("got:" in d and "want:" in d for d in diffs)


# ---------------------------------------------------------------------------
# _resolve_receipt_hashes — SAME_AS_ and skip resolution
# ---------------------------------------------------------------------------


class TestResolveReceiptHashes:
    def test_same_as_resolves_to_reference_hash(self) -> None:
        # The real vectors include receipt_optional_null_becomes_absent ==
        # SAME_AS_receipt_all_optional_absent; both must resolve to one hash.
        resolved = check._resolve_receipt_hashes(
            _vectors()["receipt_hash_vectors"]
        )
        assert "receipt_all_optional_absent" in resolved
        assert (
            resolved["receipt_optional_null_becomes_absent"]
            == resolved["receipt_all_optional_absent"]
        )

    def test_receipts_from_vector_is_omitted(self) -> None:
        # receipt_signature_preservation_legacy_0_2_0 has no `receipt` field
        # (it references receipts via receiptsFrom); it carries no byte to
        # compare and must not appear in the resolved expectations.
        resolved = check._resolve_receipt_hashes(
            _vectors()["receipt_hash_vectors"]
        )
        assert "receipt_signature_preservation_legacy_0_2_0" not in resolved

    def test_compute_at_commit_time_is_omitted(self) -> None:
        vectors = [
            {"name": "a", "receipt": {}, "expectedHash": "COMPUTE_AT_COMMIT_TIME"},
            {"name": "b", "receipt": {}, "expectedHash": "sha256:" + "1" * 64},
        ]
        resolved = check._resolve_receipt_hashes(vectors)
        assert "a" not in resolved
        assert resolved["b"] == "sha256:" + "1" * 64

    def test_unresolvable_same_as_is_omitted(self) -> None:
        # A SAME_AS_ that points at a name with no literal hash cannot be
        # asserted; it is omitted rather than compared against a missing value.
        vectors = [
            {"name": "a", "receipt": {}, "expectedHash": "SAME_AS_nonexistent"},
        ]
        assert check._resolve_receipt_hashes(vectors) == {}


# ---------------------------------------------------------------------------
# _parse_emitted — pulling the JSON output object out of a driver's stdout
# ---------------------------------------------------------------------------


class TestParseEmitted:
    def test_parses_single_json_object(self) -> None:
        obj = {"canonical": {"empty_object": "{}"}, "receipt_hash": {}}
        assert check._parse_emitted("py", check.json.dumps(obj)) == obj

    def test_ignores_leading_log_lines(self) -> None:
        obj = {"canonical": {}, "receipt_hash": {}}
        stdout = "installing...\nbuilding...\n" + check.json.dumps(obj) + "\n"
        assert check._parse_emitted("go", stdout) == obj

    def test_no_json_returns_none(self) -> None:
        assert check._parse_emitted("ts", "just some logs\nno output here\n") is None

    def test_malformed_json_returns_none(self) -> None:
        assert check._parse_emitted("py", "{ not valid json") is None

    def test_empty_stdout_returns_none(self) -> None:
        assert check._parse_emitted("go", "") is None


# ---------------------------------------------------------------------------
# _sha256 — the receipt-hash prefix helper
# ---------------------------------------------------------------------------


class TestSha256:
    def test_empty_object_canonical_hash(self) -> None:
        # sha256 of the two bytes "{}" — a known value; locks the prefix/encoding.
        assert check._sha256("{}") == (
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        )

    def test_prefix_present(self) -> None:
        assert check._sha256("anything").startswith("sha256:")


# ---------------------------------------------------------------------------
# Self-runner (no pytest dependency required)
# ---------------------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    suites = [
        TestCompareActuals,
        TestResolveReceiptHashes,
        TestParseEmitted,
        TestSha256,
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
