"""Unit tests for the run-mode decision logic in check.py.

These cover the pass/fail and no-run filtering logic without spinning up a
toolchain (the end-to-end execution itself is exercised by CI). Run with:
python3 scripts/readme_snippets/test_check.py
"""

from __future__ import annotations

import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402
import extract  # noqa: E402


def _unit(name: str, run: bool = True) -> extract.Unit:
    return extract.Unit(lang="py", name=name, code="x = 1\n", sources=[f"R.md:{name}"], run=run)


def test_runnable_excludes_no_run() -> None:
    units = [_unit("a", run=True), _unit("b", run=False), _unit("c", run=True)]
    buf = io.StringIO()
    with redirect_stdout(buf):
        runnable = check._runnable(units, "Python")
    assert [u.name for u in runnable] == ["a", "c"]
    # The skipped unit is reported, not silently dropped.
    assert "skipping (no-run)" in buf.getvalue()


def test_runnable_reports_when_nothing_runnable() -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        runnable = check._runnable([_unit("a", run=False)], "Go")
    assert runnable == []
    assert "no runnable Go units" in buf.getvalue()


def test_summarize_run_fails_when_any_snippet_fails() -> None:
    runnable = [_unit("a"), _unit("b")]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = check._summarize_run([runnable[1]], runnable, "Python")
    assert rc == 1
    assert "failed to run" in buf.getvalue()
    assert "R.md:b" in buf.getvalue()


def test_summarize_run_passes_when_no_failures() -> None:
    runnable = [_unit("a")]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = check._summarize_run([], runnable, "Python")
    assert rc == 0
    assert "ran and exited 0" in buf.getvalue()


def _run_all() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
