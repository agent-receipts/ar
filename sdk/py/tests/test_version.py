"""Test that ``agent_receipts.VERSION`` is derived from package metadata.

Pins the contract introduced in #345: replacing the hand-maintained
``VERSION = "..."`` constant with one read from ``importlib.metadata``
removes a class of release-prep drift bugs (the kind that made it past
review on #343). These tests guard against future regressions back to
hand-maintenance.
"""

from __future__ import annotations

import re
from importlib.metadata import version

import agent_receipts


def test_version_matches_installed_package_metadata() -> None:
    """``agent_receipts.VERSION`` must equal what pip / uv resolved."""

    assert agent_receipts.VERSION == version("agent-receipts")


def test_version_is_non_empty() -> None:
    """Even on the PackageNotFoundError fallback path, VERSION must be a
    non-empty string — diagnostics and crash reports that interpolate it
    should never produce ``" "`` or ``""``. Strip first so a single space
    or all-whitespace value (which would still pass a plain truthiness
    check) is also rejected."""

    assert isinstance(agent_receipts.VERSION, str)
    assert agent_receipts.VERSION.strip()


def test_version_matches_project_release_shape() -> None:
    """Catch a future regression where VERSION starts containing arbitrary
    text.

    Scope: this test enforces the Python-package version policy
    specifically — strict ``X.Y.Z`` (no leading zeros, no two-part or
    four-part variants), with an optional PEP 440 pre-release suffix
    (``aN`` / ``bN`` / ``rcN``), plus a ``+local`` tail to cover the
    ``0.0.0+unknown`` PackageNotFoundError fallback. PEP 440 disallows
    the SemVer ``-beta.1`` hyphen form that ``scripts/release.sh``'s
    ``SEMVER_RE`` accepts for the Go/TS components, so the policies
    differ on purpose; this test deliberately doesn't try to mirror
    ``release.sh`` for non-Python release shapes.

    If sdk/py ever ships ``.postN`` / ``.devN`` / epoch versions,
    broaden this regex (and update PyPI uploads accordingly)."""

    # Numeric components: zero or any positive int with no leading
    # zeros — matches the same rule release.sh's PEP440_PRE_RE applies
    # to Python pre-release numerics.
    component = r"(0|[1-9]\d*)"
    project_release_shape = re.compile(
        rf"""
        ^                                     # full match
        {component}\.{component}\.{component} # strict X.Y.Z
        ((a|b|rc)\d+)?                        # optional PEP 440 pre-release
        (\+[0-9A-Za-z.-]+)?                   # optional +local (covers +unknown)
        $
        """,
        re.VERBOSE,
    )
    assert project_release_shape.match(agent_receipts.VERSION), (
        f"VERSION {agent_receipts.VERSION!r} does not match sdk/py's "
        "release-version policy (strict X.Y.Z, optional PEP 440 aN/bN/rcN, "
        "optional +local)"
    )


def test_version_is_distinct_from_receipt_schema_version() -> None:
    """The package version (``VERSION``) and the receipt schema version
    (``RECEIPT_VERSION``) are intentionally separate — see the note in
    ``__init__.py``. Pin that the two don't accidentally converge in a
    way that would mask drift between package release and schema bump.

    The exact-equals pin on ``RECEIPT_VERSION`` lives in
    ``tests/receipt/test_types.py``; this test deliberately stays focused
    on the ``VERSION != RECEIPT_VERSION`` invariant."""

    # Both exist and are independently exported.
    assert agent_receipts.VERSION
    assert agent_receipts.RECEIPT_VERSION
    assert agent_receipts.VERSION != agent_receipts.RECEIPT_VERSION, (
        "package VERSION and RECEIPT_VERSION converged — "
        "if intentional, drop this test; otherwise one of the constants drifted"
    )
