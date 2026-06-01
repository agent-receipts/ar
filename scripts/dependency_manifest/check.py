#!/usr/bin/env python3
"""Gate #10: documented dependencies match installed dependencies (SBOM).

For the SDK being released, compare the dependencies actually resolved into the
artifact (the *installed* set) against the dependencies the SDK declares
directly (the *declared* set). Any installed dependency that is neither declared
nor allow-listed with a justification fails the gate — this catches "eager"
transitive deps that creep into a published artifact, a supply-chain concern for
a cryptographic-protocol project (AGENTS.md "Adding dependencies").

This is the release-time enforcement of the property ADR-0024 D1 records and the
SDK READMEs assert in prose ("minimal runtime dependencies — …"). The comparison
is manifest-vs-manifest: it reads the committed manifests and lockfiles only and
needs no network and no package install, so it runs against the same source the
release is cut from.

What "installed" and "declared" mean per SDK:

  - go: declared = direct ``require``s in ``go.mod``; installed = direct plus
        ``// indirect`` requires.
  - py: declared = ``[project].dependencies`` in ``pyproject.toml``; installed =
        the runtime closure of those deps resolved from ``uv.lock`` (dev /
        optional extras excluded — they are not part of the published runtime
        artifact).
  - ts: declared = runtime ``dependencies`` in ``package.json``; installed = the
        runtime closure resolved from ``pnpm-lock.yaml`` snapshots (dev deps,
        keyed under the importer's ``devDependencies``, are never reached);
        declared deps only if no lockfile is present.

Scope is the runtime closure. Dev/test/build tooling is intentionally out of
scope: it is not shipped to consumers, so an undeclared test tool is not a
supply-chain risk in the published artifact.

Usage:
    check.py --lang {go,ts,py} [--sdk-dir DIR] [--allowlist PATH]

Exit codes:
    0  every installed runtime dependency is declared or allow-listed
    1  an installed dependency is neither declared nor allow-listed
    2  usage error (missing args, unknown lang)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tomllib
from dataclasses import dataclass

# SDKs this gate knows how to inspect.
KNOWN_SDKS = ("go", "ts", "py")

# Repo root is three levels up from this file (scripts/dependency_manifest/).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.json")


# ---------------------------------------------------------------------------
# Comparison core (shared, unit-tested)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Comparison:
    """The result of comparing installed deps against declared + allow-listed deps."""

    sdk: str
    declared: frozenset[str]
    installed: frozenset[str]
    allowlisted: frozenset[str]

    @property
    def unexplained(self) -> frozenset[str]:
        """Installed deps that are neither declared nor allow-listed — these fail."""
        return self.installed - self.declared - self.allowlisted

    @property
    def stale_allowlist(self) -> frozenset[str]:
        """Allow-listed names that are not installed (drift to prune; non-fatal)."""
        return self.allowlisted - self.installed - self.declared


def _strip_pep508_name(spec: str) -> str:
    """Extract the bare package name from a PEP 508 requirement string."""
    return re.split(r"[<>=!~;\[ ]", spec.strip(), maxsplit=1)[0].strip()


def _lock_dep_name(dep: object) -> str:
    """Return the package name from a uv.lock dependency entry.

    uv.lock encodes each dependency as an inline table, e.g.
    ``{ name = "cffi", marker = "..." }``; a simpler form may be a plain string.
    Both are handled.
    """
    if isinstance(dep, dict):
        return str(dep["name"])
    return _strip_pep508_name(str(dep))


def parse_go(go_mod: str) -> tuple[set[str], set[str]]:
    """Parse a go.mod into (declared, installed) module-path sets.

    Declared = direct requires; installed = declared plus ``// indirect``
    requires. Handles both the block form ``require ( ... )`` and the
    single-line ``require <mod> <version>`` form.
    """
    declared: set[str] = set()
    indirect: set[str] = set()
    in_block = False
    require_re = re.compile(r"^(?:require\s+)?(?P<mod>[^\s(]+/[^\s]+)\s+v\S+(?P<rest>.*)$")
    for raw in go_mod.splitlines():
        stripped = raw.strip()
        if stripped.startswith("require") and stripped.endswith("("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        match = require_re.match(stripped)
        if not match:
            continue
        mod = match.group("mod")
        if "indirect" in match.group("rest"):
            indirect.add(mod)
        else:
            declared.add(mod)
    return declared, declared | indirect


def parse_py(pyproject_toml: str, uv_lock: str) -> tuple[set[str], set[str]]:
    """Parse Python manifests into (declared, installed) runtime-dependency sets.

    Declared = ``[project].dependencies``. Installed = the runtime closure of
    those declared deps resolved from ``uv.lock``. Dev/optional extras are
    excluded: they are not part of the published runtime artifact.
    """
    project = tomllib.loads(pyproject_toml)["project"]
    declared = {_strip_pep508_name(d) for d in project.get("dependencies", [])}

    lock = tomllib.loads(uv_lock)
    by_name = {pkg["name"]: pkg for pkg in lock.get("package", [])}

    installed: set[str] = set()
    stack = list(declared)
    while stack:
        name = stack.pop()
        if name in installed:
            continue
        installed.add(name)
        pkg = by_name.get(name)
        if pkg is None:
            continue
        for dep in pkg.get("dependencies", []):
            stack.append(_lock_dep_name(dep))
    return declared, installed


def _pnpm_spec_to_name(spec: str) -> str:
    """Reduce a pnpm-lock key/value (``'name@1.2.3(peer)'``) to its package name."""
    spec = spec.strip().strip("'\"")
    spec = re.sub(r"\(.*\)$", "", spec)  # drop a trailing "(peer@x)" suffix
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec  # at>0 keeps a leading "@scope/" intact


def parse_pnpm_snapshots(pnpm_lock: str) -> dict[str, set[str]]:
    """Map each resolved package name to its runtime dependency names.

    Reads the ``snapshots:`` section of a pnpm-lock.yaml (lockfileVersion 9)
    without a YAML library. Each snapshot key is ``'<name>@<version>(peers)':``
    and may contain ``dependencies:`` / ``optionalDependencies:`` sub-blocks
    whose entries are runtime deps. Optional deps are folded in (they ship when
    present); ``transitivePeerDependencies:`` and other metadata are ignored.
    """
    result: dict[str, set[str]] = {}
    in_snapshots = False
    current: str | None = None
    in_deps = False
    for line in pnpm_lock.splitlines():
        if re.match(r"^\S", line):  # a new top-level section starts
            in_snapshots = line.startswith("snapshots:")
            current = None
            in_deps = False
            continue
        if not in_snapshots:
            continue
        m_key = re.match(r"^  (?P<key>'[^']+'|[^:\s][^:]*):\s*$", line)
        if m_key:
            current = _pnpm_spec_to_name(m_key.group("key"))
            result.setdefault(current, set())
            in_deps = False
            continue
        m_sub = re.match(r"^    (?P<sub>\w+):\s*$", line)
        if m_sub:
            in_deps = m_sub.group("sub") in ("dependencies", "optionalDependencies")
            continue
        if in_deps and current is not None:
            m_dep = re.match(r"^      (?P<name>'[^']+'|[^:\s]+):", line)
            if m_dep:
                result[current].add(_pnpm_spec_to_name(m_dep.group("name")))
    return result


def parse_ts(package_json: str, pnpm_lock: str | None) -> tuple[set[str], set[str]]:
    """Parse package.json (+ optional pnpm-lock.yaml) into (declared, installed).

    Declared = runtime ``dependencies`` keys. Installed = the runtime
    dependency closure resolved from the lockfile when available; without a
    lockfile the transitive runtime tree cannot be resolved offline, so
    installed == declared.
    """
    data = json.loads(package_json)
    declared = set(data.get("dependencies", {}))
    if pnpm_lock is None:
        return declared, set(declared)

    snapshots = parse_pnpm_snapshots(pnpm_lock)
    installed: set[str] = set()
    stack = list(declared)
    while stack:
        name = stack.pop()
        if name in installed:
            continue
        installed.add(name)
        for dep in snapshots.get(name, ()):
            stack.append(dep)
    return declared, installed


def installed_and_declared(sdk: str, sdk_dir: str) -> tuple[set[str], set[str]]:
    """Return (declared, installed) dependency name sets for an SDK directory."""

    def read(name: str) -> str:
        with open(os.path.join(sdk_dir, name), encoding="utf-8") as fh:
            return fh.read()

    if sdk == "go":
        return parse_go(read("go.mod"))
    if sdk == "ts":
        lock_path = os.path.join(sdk_dir, "pnpm-lock.yaml")
        lock = read("pnpm-lock.yaml") if os.path.exists(lock_path) else None
        return parse_ts(read("package.json"), lock)
    if sdk == "py":
        return parse_py(read("pyproject.toml"), read("uv.lock"))
    raise ValueError(f"unknown sdk: {sdk!r} (expected one of {KNOWN_SDKS})")


def compare(sdk: str, sdk_dir: str, allowlisted: set[str]) -> Comparison:
    """Build a Comparison for one SDK from its on-disk manifests and an allowlist."""
    declared, installed = installed_and_declared(sdk, sdk_dir)
    return Comparison(
        sdk=sdk,
        declared=frozenset(declared),
        installed=frozenset(installed),
        allowlisted=frozenset(allowlisted),
    )


def load_allowlist(path: str, sdk: str) -> set[str]:
    """Load allow-listed dependency names for one SDK from an allowlist.json."""
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {entry["name"] for entry in data.get(sdk, [])}


def _report(result: Comparison) -> int:
    """Print pass/fail for a Comparison. Returns 0 when nothing is unexplained."""
    sdk = result.sdk
    for name in sorted(result.unexplained):
        print(
            f"::error::sdk/{sdk}: installed dependency {name!r} is not declared and "
            f"not allow-listed — add it to scripts/dependency_manifest/allowlist.json "
            f"with a justification, or remove the dependency"
        )
    for name in sorted(result.stale_allowlist):
        print(
            f"::warning::sdk/{sdk}: allow-listed dependency {name!r} is not installed "
            f"(stale allowlist entry — prune it)"
        )
    if result.unexplained:
        print(
            f"ERROR: {len(result.unexplained)} undeclared, un-allow-listed "
            f"dependency(ies) in sdk/{sdk}"
        )
        return 1
    print(
        f"OK: sdk/{sdk}: all {len(result.installed)} installed runtime "
        f"dependency(ies) are declared or allow-listed"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--lang", required=True, choices=list(KNOWN_SDKS))
    parser.add_argument(
        "--sdk-dir",
        default=None,
        help="SDK directory to inspect (default: <repo>/sdk/<lang>)",
    )
    parser.add_argument(
        "--allowlist",
        default=DEFAULT_ALLOWLIST,
        help=f"Path to the allowlist JSON (default: {DEFAULT_ALLOWLIST})",
    )
    args = parser.parse_args(argv)

    sdk = args.lang
    sdk_dir = args.sdk_dir or os.path.join(_REPO_ROOT, "sdk", sdk)
    allowlisted = load_allowlist(args.allowlist, sdk)

    print("Gate #10 — documented dependencies match installed dependencies")
    print(f"  lang      : {sdk}")
    print(f"  sdk-dir   : {sdk_dir}")
    print(f"  allowlist : {args.allowlist}")

    result = compare(sdk, sdk_dir, allowlisted)
    rc = _report(result)

    if rc == 0:
        print(f"\nGate #10 PASSED for {sdk}")
    else:
        print(f"\nGate #10 FAILED for {sdk} (see errors above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
