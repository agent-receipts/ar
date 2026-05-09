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
    text. This isn't a full PEP 440 validator (it doesn't accept epochs,
    post releases, or dev releases) — the project deliberately only ever
    ships standard / pre-release semver + the ``0.0.0+unknown`` fallback,
    so the regex is intentionally narrow. If the project starts shipping
    `.postN` or `.devN` builds, broaden the pattern at that point."""

    project_release_shape = re.compile(
        r"""
        ^                    # full match
        \d+(\.\d+)*          # release segment (e.g. 0.8.0)
        (a\d+|b\d+|rc\d+)?   # optional pre-release (a1, b2, rc3)
        (\+[a-zA-Z0-9.]+)?   # optional local version (+unknown, +g1234abcd)
        $
        """,
        re.VERBOSE,
    )
    assert project_release_shape.match(agent_receipts.VERSION), (
        f"VERSION {agent_receipts.VERSION!r} does not match the shapes this "
        "project releases (semver + optional aN/bN/rcN + optional +local)"
    )


def test_version_is_distinct_from_receipt_schema_version() -> None:
    """The package version (``VERSION``) and the receipt schema version
    (``RECEIPT_VERSION``) are intentionally separate — see the note in
    ``__init__.py``. Pin that the two don't accidentally converge in a
    way that would mask drift between package release and schema bump."""

    # Both exist and are independently exported.
    assert agent_receipts.VERSION
    assert agent_receipts.RECEIPT_VERSION
    # The headline invariant the test name promises: package version and
    # schema version are separate values from separate sources.
    assert agent_receipts.VERSION != agent_receipts.RECEIPT_VERSION, (
        "package VERSION and RECEIPT_VERSION converged — "
        "if intentional, drop this test; otherwise one of the constants drifted"
    )
    # Belt-and-braces: schema version stays in the 0.2.x range
    # (per receipt/types.py). If this ever fails, the schema bumped —
    # review whether the test still expresses the right invariant.
    schema = agent_receipts.RECEIPT_VERSION
    assert schema.startswith("0.2."), (
        f"receipt schema version moved past 0.2.x ({schema!r}); "
        "update this guard if intentional"
    )
