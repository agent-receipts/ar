"""Unit tests for the Gate #10 dependency-manifest verifier.

These tests exercise the comparison core (the per-language manifest parsers and
the declared-vs-installed comparison) against controlled fixtures, plus the
shipped allowlist against the real SDK manifests. No package is installed and no
network call is made — the comparison reads committed files only.

The core invariant under test: an installed dependency that is neither declared
nor allow-listed is flagged as `unexplained` (the gate fails), and the shipped
allowlist explains every undeclared dependency in every real SDK (the gate
passes on `main`). The fail case is a direct implementation of ADR-0024 D6 (a
gate must be observed to fail on a deliberately-broken input).

Run with:
    python3 -m pytest scripts/dependency_manifest/test_check.py
    python3 scripts/dependency_manifest/test_check.py   # quick self-check
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402

GO_MOD_SINGLE = """\
module example.com/x

go 1.23

require golang.org/x/crypto v0.31.0

require golang.org/x/sys v0.28.0 // indirect
"""

GO_MOD_BLOCK = """\
module example.com/x

go 1.23

require (
\tgolang.org/x/crypto v0.31.0
)

require (
\tgolang.org/x/sys v0.28.0 // indirect
)
"""

PYPROJECT = """\
[project]
name = "demo"
version = "0.1.0"
dependencies = ["cryptography>=43.0.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
"""

UV_LOCK = """\
version = 1

[[package]]
name = "demo"
source = { editable = "." }
dependencies = [
    { name = "cryptography" },
]

[[package]]
name = "cryptography"
dependencies = [
    { name = "cffi", marker = "platform_python_implementation != 'PyPy'" },
]

[[package]]
name = "cffi"
dependencies = [
    { name = "pycparser" },
]

[[package]]
name = "pycparser"

[[package]]
name = "pytest"
dependencies = [
    { name = "pluggy" },
]

[[package]]
name = "pluggy"
"""

PACKAGE_JSON = '{"dependencies": {"undici": "^8.3.0", "zod": "^4.4.2"}}'

PNPM_LOCK = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      undici:
        specifier: ^8.3.0
        version: 8.3.0
      zod:
        specifier: ^4.4.2
        version: 4.4.3
    devDependencies:
      vitest:
        specifier: ^4.1.2
        version: 4.1.7

packages:

  undici@8.3.0:
    resolution: {integrity: sha512-aaa==}

  zod@4.4.3:
    resolution: {integrity: sha512-bbb==}

  vitest@4.1.7:
    resolution: {integrity: sha512-ccc==}

snapshots:

  undici@8.3.0: {}

  zod@4.4.3: {}

  vitest@4.1.7:
    dependencies:
      sneaky-transitive: 1.0.0

  sneaky-transitive@1.0.0: {}
"""


# ---------------------------------------------------------------------------
# parse_go — direct vs indirect requires
# ---------------------------------------------------------------------------


class TestParseGo:
    def test_single_line_requires(self) -> None:
        declared, installed = check.parse_go(GO_MOD_SINGLE)
        assert declared == {"golang.org/x/crypto"}
        assert installed == {"golang.org/x/crypto", "golang.org/x/sys"}

    def test_block_requires(self) -> None:
        declared, installed = check.parse_go(GO_MOD_BLOCK)
        assert declared == {"golang.org/x/crypto"}
        assert installed == {"golang.org/x/crypto", "golang.org/x/sys"}


# ---------------------------------------------------------------------------
# parse_py — runtime closure from uv.lock, dev extras excluded
# ---------------------------------------------------------------------------


class TestParsePy:
    def test_runtime_closure_resolves_dict_deps(self) -> None:
        # uv.lock encodes deps as inline tables ({ name = ..., marker = ... }).
        declared, installed = check.parse_py(PYPROJECT, UV_LOCK)
        assert declared == {"cryptography"}
        assert installed == {"cryptography", "cffi", "pycparser"}

    def test_dev_tooling_is_excluded(self) -> None:
        _, installed = check.parse_py(PYPROJECT, UV_LOCK)
        assert "pytest" not in installed
        assert "pluggy" not in installed


# ---------------------------------------------------------------------------
# parse_ts — runtime closure from pnpm-lock snapshots, dev tree excluded
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_resolves_runtime_closure_excludes_dev_tree(self) -> None:
        declared, installed = check.parse_ts(PACKAGE_JSON, PNPM_LOCK)
        assert declared == {"undici", "zod"}
        # The dev tool's transitive must not leak into the runtime set.
        assert installed == {"undici", "zod"}
        assert "sneaky-transitive" not in installed

    def test_without_lockfile_falls_back_to_declared(self) -> None:
        declared, installed = check.parse_ts(PACKAGE_JSON, None)
        assert declared == installed == {"undici", "zod"}

    def test_scoped_package_name_preserved(self) -> None:
        # A leading @scope/ must survive the version strip.
        assert check._pnpm_spec_to_name("'@noble/ed25519@2.1.0'") == "@noble/ed25519"
        assert check._pnpm_spec_to_name("zod@4.4.3(peer@1.0.0)") == "zod"


# ---------------------------------------------------------------------------
# Comparison — the pass/fail decision
# ---------------------------------------------------------------------------


class TestComparison:
    def test_flags_undeclared_unallowlisted(self) -> None:
        c = check.Comparison(
            sdk="py",
            declared=frozenset({"cryptography"}),
            installed=frozenset({"cryptography", "cffi", "pycparser"}),
            allowlisted=frozenset({"cffi"}),
        )
        assert c.unexplained == frozenset({"pycparser"})

    def test_passes_when_all_allowlisted(self) -> None:
        c = check.Comparison(
            sdk="py",
            declared=frozenset({"cryptography"}),
            installed=frozenset({"cryptography", "cffi", "pycparser"}),
            allowlisted=frozenset({"cffi", "pycparser"}),
        )
        assert c.unexplained == frozenset()

    def test_reports_stale_allowlist(self) -> None:
        c = check.Comparison(
            sdk="go",
            declared=frozenset({"golang.org/x/crypto"}),
            installed=frozenset({"golang.org/x/crypto"}),
            allowlisted=frozenset({"golang.org/x/sys"}),
        )
        assert c.stale_allowlist == frozenset({"golang.org/x/sys"})


# ---------------------------------------------------------------------------
# compare + _report — gate blocks on an injected eager dependency
# ---------------------------------------------------------------------------


class TestGateBlocks:
    def test_compare_blocks_unexplained_dep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sdk_dir = os.path.join(tmp, "go")
            os.makedirs(sdk_dir)
            with open(os.path.join(sdk_dir, "go.mod"), "w", encoding="utf-8") as fh:
                fh.write(GO_MOD_SINGLE)
            blocked = check.compare("go", sdk_dir, allowlisted=set())
            assert blocked.unexplained == frozenset({"golang.org/x/sys"})
            assert check._report(blocked) == 1
            allowed = check.compare("go", sdk_dir, allowlisted={"golang.org/x/sys"})
            assert allowed.unexplained == frozenset()
            assert check._report(allowed) == 0

    def test_unknown_sdk_rejected(self) -> None:
        try:
            check.installed_and_declared("rust", "/nonexistent")
        except ValueError:
            return
        raise AssertionError("expected ValueError for unknown sdk")


# ---------------------------------------------------------------------------
# Shipped allowlist vs the real SDK manifests
# ---------------------------------------------------------------------------


class TestShippedAllowlist:
    def test_real_manifests_pass_with_committed_allowlist(self) -> None:
        for sdk in check.KNOWN_SDKS:
            allow = check.load_allowlist(check.DEFAULT_ALLOWLIST, sdk)
            sdk_dir = os.path.join(check._REPO_ROOT, "sdk", sdk)
            result = check.compare(sdk, sdk_dir, allow)
            assert result.unexplained == frozenset(), (sdk, result.unexplained)

    def test_committed_allowlist_entries_have_justifications(self) -> None:
        with open(check.DEFAULT_ALLOWLIST, encoding="utf-8") as fh:
            data = json.load(fh)
        assert set(data) <= set(check.KNOWN_SDKS)
        for sdk, entries in data.items():
            for entry in entries:
                assert entry["name"], (sdk, entry)
                assert entry["justification"].strip(), (sdk, entry)

    def test_no_stale_allowlist_entries(self) -> None:
        for sdk in check.KNOWN_SDKS:
            allow = check.load_allowlist(check.DEFAULT_ALLOWLIST, sdk)
            sdk_dir = os.path.join(check._REPO_ROOT, "sdk", sdk)
            result = check.compare(sdk, sdk_dir, allow)
            assert result.stale_allowlist == frozenset(), (sdk, result.stale_allowlist)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_passes_on_real_go(self) -> None:
        assert check.main(["--lang", "go"]) == 0

    def test_main_fails_on_injected_dep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "go.mod"), "w", encoding="utf-8") as fh:
                fh.write(GO_MOD_SINGLE)
            empty = os.path.join(tmp, "empty-allowlist.json")
            with open(empty, "w", encoding="utf-8") as fh:
                fh.write("{}")
            rc = check.main(["--lang", "go", "--sdk-dir", tmp, "--allowlist", empty])
            assert rc == 1


# ---------------------------------------------------------------------------
# Self-runner (no pytest dependency required)
# ---------------------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    suites = [
        TestParseGo,
        TestParsePy,
        TestParseTs,
        TestComparison,
        TestGateBlocks,
        TestShippedAllowlist,
        TestMain,
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
