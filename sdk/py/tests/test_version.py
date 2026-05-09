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
    should never produce ``" "`` or ``""``."""

    assert isinstance(agent_receipts.VERSION, str)
    assert agent_receipts.VERSION  # truthy / non-empty


def test_version_is_pep440_shaped() -> None:
    """Catch a future regression where VERSION starts containing arbitrary
    text. PEP 440 + the project's ``0.0.0+unknown`` fallback covers every
    string we should ever surface."""

    pep440_or_fallback = re.compile(
        r"""
        ^                    # full match
        \d+(\.\d+)*          # release segment (e.g. 0.8.0)
        (a\d+|b\d+|rc\d+)?   # optional pre-release (a1, b2, rc3)
        (\+[a-zA-Z0-9.]+)?   # optional local version (+unknown, +g1234abcd)
        $
        """,
        re.VERBOSE,
    )
    assert pep440_or_fallback.match(agent_receipts.VERSION), (
        f"VERSION {agent_receipts.VERSION!r} does not look like a PEP 440 version"
    )


def test_version_is_distinct_from_receipt_schema_version() -> None:
    """The package version (``VERSION``) and the receipt schema version
    (``RECEIPT_VERSION``) are intentionally separate — see the note in
    ``__init__.py``. Pin that the two don't accidentally converge in a
    way that would mask drift between package release and schema bump."""

    # Both exist and are independently exported.
    assert agent_receipts.VERSION
    assert agent_receipts.RECEIPT_VERSION
    # Sanity: schema version stays at 0.2.x range (per receipt/types.py).
    # If this ever fails, the schema bumped — review whether the test
    # still expresses the right invariant.
    schema = agent_receipts.RECEIPT_VERSION
    assert schema.startswith("0.2."), (
        f"receipt schema version moved past 0.2.x ({schema!r}); "
        "update this guard if intentional"
    )
