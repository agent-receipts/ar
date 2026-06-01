"""Unit tests for the usage-signal classifier.

These exercise the pure classification core (`classify_series`,
`classify_versions`, `verdict`, and the `active_window`/`spike_threshold_for`
helpers) against synthetic machine- and human-shaped inputs. No network call is
made — the fetchers that hit api.npmjs.org / pypistats.org / pkg.go.dev are thin
I/O wrappers exercised against the live services by hand, not here.

The invariant under test: traffic that is flat across the week, dominated by
publish-day spikes, smeared across pre-release versions, or mostly mirror hits
classifies as machine-dominated; traffic with a weekday-skewed baseline
concentrated on the latest version classifies as human-leaning. Both directions
are asserted, so a classifier that always answers "machine" fails the
human-shaped cases.

Run with:
    python3 -m pytest scripts/usage_signal/test_check.py
    python3 scripts/usage_signal/test_check.py   # quick self-check
"""

from __future__ import annotations

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import check  # noqa: E402

MONDAY = datetime.date(2026, 4, 6)  # a known Monday, for weekday-shaped fixtures


def _days(start: datetime.date, counts: list[int]) -> list[tuple[datetime.date, int]]:
    return [(start + datetime.timedelta(days=i), n) for i, n in enumerate(counts)]


def _machine_series() -> list[tuple[datetime.date, int]]:
    """Flat 7/day for 8 weeks, with a 200-download spike every 7th day."""
    counts = []
    for i in range(56):
        counts.append(200 if i % 7 == 0 else 7)
    return _days(MONDAY, counts)


def _human_series() -> list[tuple[datetime.date, int]]:
    """Weekday-heavy, no spikes: 20/day Mon-Fri, 3/day Sat-Sun, for 8 weeks."""
    counts = []
    for i in range(56):
        dow = (MONDAY + datetime.timedelta(days=i)).weekday()
        counts.append(3 if dow >= 5 else 20)
    return _days(MONDAY, counts)


# --- active_window / spike_threshold_for -----------------------------------


def test_active_window_trims_leading_and_trailing_zeros() -> None:
    series = _days(datetime.date(2026, 1, 1), [0, 0, 5, 0, 8, 0, 0])
    window = check.active_window(series)
    assert [n for _, n in window] == [5, 0, 8], window


def test_active_window_all_zero_is_empty() -> None:
    assert check.active_window(_days(datetime.date(2026, 1, 1), [0, 0, 0])) == []


def test_spike_threshold_scales_with_median_but_has_floor() -> None:
    # tiny package: floor wins
    assert check.spike_threshold_for([1, 2, 3, 2]) == check.SPIKE_FLOOR
    # busy package: 10 * median(=100) = 1000 wins over the floor
    assert check.spike_threshold_for([100] * 9 + [5000]) == 1000


# --- classify_series --------------------------------------------------------


def test_classify_none_when_no_downloads() -> None:
    assert check.classify_series(_days(datetime.date(2026, 1, 1), [0, 0, 0])) is None


def test_machine_series_is_spiky_and_flat_week() -> None:
    m = check.classify_series(_machine_series())
    assert m is not None
    assert m.spike_days == 8
    assert m.spike_share > 0.5  # spikes dominate the volume
    # baseline is a flat 7/day every day -> weekend ~= weekday
    assert check.FLAT_WEEK_LO <= m.weekend_weekday_ratio <= check.FLAT_WEEK_HI


def test_human_series_is_weekday_skewed_no_spikes() -> None:
    m = check.classify_series(_human_series())
    assert m is not None
    assert m.spike_days == 0
    assert m.zero_days == 0
    assert m.weekend_weekday_ratio < check.HUMAN_WEEKDAY_RATIO  # 3/20 = 0.15


# --- classify_versions ------------------------------------------------------


def test_versions_mirror_smear_flags_prereleases_and_low_top_share() -> None:
    # real last-week distribution: latest is the plurality but a minority,
    # the rest smeared evenly across stable and abandoned pre-release versions.
    v = check.classify_versions(
        {
            "0.10.0": 27,
            "0.9.0": 8,
            "0.9.0-alpha.1": 8,
            "0.8.0": 4,
            "0.8.0-alpha.1": 4,
            "0.8.0-alpha.2": 3,
            "0.6.0": 3,
            "0.5.0": 4,
            "0.4.1": 2,
            "0.4.0": 4,
            "0.3.0": 3,
            "0.2.2": 3,
            "0.2.1": 3,
            "0.2.0": 3,
        }
    )
    assert v is not None
    assert v.prerelease_versions == 3
    assert v.top_version == "0.10.0"
    assert v.top_share < 0.5  # 27/79 ~= 0.34, smeared across history


def test_versions_human_concentrates_on_latest() -> None:
    v = check.classify_versions({"0.10.0": 90, "0.9.0": 5, "0.8.0": 5})
    assert v is not None
    assert v.prerelease_versions == 0
    assert v.top_share >= 0.5


# --- verdict ----------------------------------------------------------------


def test_verdict_machine_for_machine_inputs() -> None:
    m = check.classify_series(_machine_series())
    v = check.classify_versions({"0.2.0": 3, "0.3.0": 3, "0.4.0-alpha.1": 4, "0.5.0": 4})
    label, notes = check.verdict(m, v, mirror_fraction=0.8)
    assert label.startswith("machine")
    assert notes


def test_verdict_human_for_human_inputs() -> None:
    m = check.classify_series(_human_series())
    v = check.classify_versions({"0.10.0": 90, "0.9.0": 5})
    label, notes = check.verdict(m, v, mirror_fraction=0.1)
    assert label.startswith("human"), (label, notes)


def test_verdict_no_data() -> None:
    label, _ = check.verdict(None)
    assert label == "no data"


# --- release assets (Homebrew / GitHub Releases) ---------------------------


def test_parse_asset_platform_skips_non_binaries() -> None:
    assert check.parse_asset_platform("checksums.txt") is None
    assert check.parse_asset_platform("mcp-proxy_0.12.0_darwin_arm64.tar.gz") == "darwin"
    assert check.parse_asset_platform("agent-receipts-hook_0.12.0_linux_amd64.tar.gz") == "linux"


def test_release_assets_desktop_dominated_is_human() -> None:
    # the real hook + mcp-proxy v0.12.0 shape: all darwin_arm64, zero linux,
    # zero checksums -> no sweep, all human
    releases = [
        [
            ("agent-receipts-hook_0.12.0_darwin_arm64.tar.gz", 11),
            ("agent-receipts-hook_0.12.0_darwin_amd64.tar.gz", 1),
            ("agent-receipts-hook_0.12.0_linux_amd64.tar.gz", 0),
            ("checksums.txt", 0),
        ],
        [
            ("mcp-proxy_0.12.0_darwin_arm64.tar.gz", 9),
            ("mcp-proxy_0.12.0_linux_arm64.tar.gz", 0),
            ("checksums.txt", 0),
        ],
    ]
    m = check.classify_release_assets(releases)
    assert m is not None
    assert m.total_downloads == 21
    assert m.server_downloads == 0
    assert m.ci_sweep_releases == 0
    assert m.human_downloads == 21
    assert m.by_module == {"agent-receipts-hook": 12, "mcp-proxy": 9}
    label, _ = check.verdict_release(m)
    assert label.startswith("human-leaning")


def test_release_assets_sweep_detected_and_discounted() -> None:
    # the real mcp-proxy/collector v0.13.0 shape: 1 of every platform + checksums
    # (CI sweep) alongside the human darwin_arm64 column
    releases = [
        [
            ("mcp-proxy_0.13.0_darwin_amd64.tar.gz", 1),
            ("mcp-proxy_0.13.0_darwin_arm64.tar.gz", 3),
            ("mcp-proxy_0.13.0_linux_amd64.tar.gz", 1),
            ("mcp-proxy_0.13.0_linux_arm64.tar.gz", 1),
            ("checksums.txt", 1),
        ],
        [
            ("collector_0.13.0_darwin_amd64.tar.gz", 1),
            ("collector_0.13.0_darwin_arm64.tar.gz", 7),
            ("collector_0.13.0_linux_amd64.tar.gz", 1),
            ("collector_0.13.0_linux_arm64.tar.gz", 1),
            ("checksums.txt", 1),
        ],
    ]
    m = check.classify_release_assets(releases)
    assert m is not None
    assert m.ci_sweep_releases == 2
    assert m.ci_downloads == 8  # 4 binary artifacts swept per release
    assert m.human_downloads == 8  # 16 binary downloads - 8 swept
    label, notes = check.verdict_release(m)
    assert label.startswith("human-leaning")
    assert any("CI sweep" in n for n in notes)


def test_release_assets_linux_dominated_is_ci() -> None:
    releases = [
        [
            ("mcp-proxy_1.0.0_linux_amd64.tar.gz", 80),
            ("mcp-proxy_1.0.0_darwin_arm64.tar.gz", 3),
        ]
    ]
    m = check.classify_release_assets(releases)
    assert m is not None
    label, _ = check.verdict_release(m)
    assert "Linux-dominated" in label


def test_release_assets_none_when_undownloaded() -> None:
    assert check.classify_release_assets([[("x_1.0_linux_amd64.tar.gz", 0)]]) is None


# --- runner -----------------------------------------------------------------


def _run_all() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"ok   {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
