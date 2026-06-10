"""Package version, derived from installed package metadata.

Reading the version from ``importlib.metadata`` keeps it in lockstep with
``pyproject.toml`` automatically. ``pyproject.toml`` is the single source
of truth.

If the package is imported from a checkout that hasn't been installed,
``importlib.metadata.version`` raises ``PackageNotFoundError``. We surface
a clearly-fake fallback so a stray import in such an environment doesn't
crash — but every supported install path makes the metadata available.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def _resolve_version() -> str:
    try:
        return version("agent-receipts-hermes")
    except PackageNotFoundError:
        return "0.0.0+unknown"


VERSION = _resolve_version()
