#!/usr/bin/env python3
"""Usage-signal check: tell real adopters apart from mirrors, CI, and scanners.

For a young package the public download counters lie. npm's number folds in,
with no opt-out, every registry mirror (Cloudflare, Yarn, regional mirrors that
clone the whole version history), every security scanner (Socket, Snyk,
Dependabot, Renovate), every proxy cache, and your own release CI. PyPI is the
same minus the mirrors, which it at least lets you subtract. Go publishes no
download count at all. So the raw total is close to meaningless on its own — you
have to read the *shape* of the traffic, not its size.

This tool pulls the shape for every package this monorepo ships and prints a
machine-vs-human verdict per ecosystem. The three signals it reads:

1. Daily-series shape (npm, PyPI). Real human adoption leaves a persistent,
   weekday-skewed baseline that does not drop to zero and does not consist of
   one-day bursts. Automated traffic is the opposite: flat across the week
   (mirrors and scanners don't take weekends off) and dominated by same-day
   spikes that react to your own publishes and then decay within ~48h.

2. Per-version distribution (npm). A mirror clones *every* version, including
   abandoned pre-releases nobody would install fresh, so downloads smear evenly
   across the whole history. A human installs the latest one or two.

3. Adoption-by-reference (PyPI mirror split, Go imported-by, GitHub dependents).
   The strongest signal there is: someone committed your package to their
   manifest. PyPI's ``without_mirrors`` series strips mirror noise outright; Go
   has no counter but ``pkg.go.dev`` reports an imported-by count.

The classification core (``classify_series``, ``classify_versions``,
``verdict``) is pure and takes no network, so the unit tests exercise it
directly with synthetic machine- and human-shaped inputs. The fetchers are thin
I/O wrappers, best-effort: a source that fails to fetch is reported as
unavailable rather than aborting the run.

Usage:
    check.py [--npm PKG ...] [--pypi PKG ...] [--go MODULE ...]
             [--no-npm] [--no-pypi] [--go-off] [--json]

With no package flags it uses this repo's published packages. Network egress to
api.npmjs.org, pypistats.org, and pkg.go.dev is required for live data; the
``npm view`` publish-date lookup additionally needs the npm CLI on PATH.

Exit codes:
    0  ran and printed a report (even if some sources were unavailable)
    2  usage error
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import statistics
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

# ---------------------------------------------------------------------------
# Defaults for this monorepo

NPM_PACKAGES = ["@agnt-rcpt/sdk-ts", "@agnt-rcpt/sdk-ts-aws"]
PYPI_PACKAGES = ["agent-receipts"]
GO_MODULES = ["github.com/agent-receipts/ar/sdk/go"]
GITHUB_REPO = "agent-receipts/ar"

# Binary modules shipped as GitHub Release assets and installed via the Homebrew
# tap (brew install agent-receipts/tap/<module>). brew fetches the release
# tarball straight from GitHub, so the asset download_count is a clean install
# signal — registry mirrors and package scanners don't pull release binaries.
GITHUB_BINARY_MODULES = ["hook", "mcp-proxy", "daemon", "collector"]

# ---------------------------------------------------------------------------
# Classification thresholds. A "spike" is a publish/mirror reaction day; the
# default threshold is relative to the package's own baseline so it scales from
# a 5/day package to a 5000/day one, with an absolute floor so a near-dead
# package doesn't promote its own noise to "spike".

SPIKE_FACTOR = 10  # a day above SPIKE_FACTOR * median(nonzero) is a spike
SPIKE_FLOOR = 50  # ...but never below this absolute count

# weekend/weekday ratio bands. Humans install at work, so genuine adoption
# skews to weekdays (ratio well below 1). A flat week is a machine week.
FLAT_WEEK_LO, FLAT_WEEK_HI = 0.7, 1.4
HUMAN_WEEKDAY_RATIO = 0.7  # weekend/weekday below this leans human

# Release-asset platform split. CI and containers are Linux; humans installing a
# CLI via Homebrew are on macOS/Windows desktops. A desktop-dominated mix with
# little Linux is a human-laptop signal, not automation.
DESKTOP_FRACTION_HUMAN = 0.6

HTTP_TIMEOUT = 20
USER_AGENT = "agent-receipts-usage-signal/1.0 (+https://github.com/agent-receipts/ar)"


# ---------------------------------------------------------------------------
# Pure classification core (no network)


@dataclass
class SeriesMetrics:
    """Shape metrics for a daily download series over its active window."""

    total: int
    active_days: int
    spike_threshold: int
    spike_days: int
    spike_share: float  # fraction of all downloads landing on spike days
    baseline_median: float  # median of non-spike days
    baseline_mean: float
    zero_days: int  # non-spike days with literally zero downloads
    weekday_per_day: float  # mean baseline downloads on Mon-Fri
    weekend_per_day: float  # mean baseline downloads on Sat-Sun
    weekend_weekday_ratio: float  # weekend_per_day / weekday_per_day, 0 if N/A


def active_window(series: list[tuple[datetime.date, int]]) -> list[tuple[datetime.date, int]]:
    """Trim leading and trailing all-zero runs (pre-launch / future padding)."""
    nz = [i for i, (_, n) in enumerate(series) if n > 0]
    if not nz:
        return []
    return series[nz[0] : nz[-1] + 1]


def spike_threshold_for(values: list[int]) -> int:
    """Threshold above which a day counts as a publish/mirror spike."""
    nonzero = [v for v in values if v > 0]
    if not nonzero:
        return SPIKE_FLOOR
    return max(SPIKE_FLOOR, int(SPIKE_FACTOR * statistics.median(nonzero)))


def classify_series(
    series: list[tuple[datetime.date, int]],
    spike_threshold: int | None = None,
) -> SeriesMetrics | None:
    """Reduce a daily series to shape metrics over its active window.

    Returns ``None`` if the series never had a download (nothing to classify).
    Weekday/weekend means are computed on baseline (non-spike) days only, so a
    burst of mirror traffic on a publish day cannot masquerade as a human floor.
    """
    window = active_window(series)
    if not window:
        return None

    values = [n for _, n in window]
    threshold = spike_threshold if spike_threshold is not None else spike_threshold_for(values)

    baseline = [(d, n) for d, n in window if n < threshold]
    spike = [(d, n) for d, n in window if n >= threshold]
    base_vals = [n for _, n in baseline]

    weekday = [n for d, n in baseline if d.weekday() < 5]
    weekend = [n for d, n in baseline if d.weekday() >= 5]
    weekday_per_day = statistics.mean(weekday) if weekday else 0.0
    weekend_per_day = statistics.mean(weekend) if weekend else 0.0
    ratio = (weekend_per_day / weekday_per_day) if weekday_per_day else 0.0

    return SeriesMetrics(
        total=sum(values),
        active_days=len(window),
        spike_threshold=threshold,
        spike_days=len(spike),
        spike_share=(sum(n for _, n in spike) / sum(values)) if sum(values) else 0.0,
        baseline_median=statistics.median(base_vals) if base_vals else 0.0,
        baseline_mean=statistics.mean(base_vals) if base_vals else 0.0,
        zero_days=sum(1 for n in base_vals if n == 0),
        weekday_per_day=weekday_per_day,
        weekend_per_day=weekend_per_day,
        weekend_weekday_ratio=ratio,
    )


@dataclass
class VersionMetrics:
    """Per-version download distribution shape (npm)."""

    versions_with_downloads: int
    prerelease_versions: int  # pre-releases (X.Y.Z-...) still pulling downloads
    top_version: str
    top_share: float  # fraction of the week's downloads on the single top version


def classify_versions(version_downloads: dict[str, int]) -> VersionMetrics | None:
    """Summarise how downloads spread across published versions.

    Pre-releases drawing steady traffic, and a low share on the top version, are
    mirror fingerprints — no human installs ``X.Y.Z-alpha.1`` once a stable
    release exists.
    """
    active = {v: n for v, n in version_downloads.items() if n > 0}
    if not active:
        return None
    total = sum(active.values())
    top_version, top_n = max(active.items(), key=lambda kv: kv[1])
    return VersionMetrics(
        versions_with_downloads=len(active),
        prerelease_versions=sum(1 for v in active if "-" in v),
        top_version=top_version,
        top_share=top_n / total,
    )


def verdict(
    metrics: SeriesMetrics | None,
    versions: VersionMetrics | None = None,
    mirror_fraction: float | None = None,
) -> tuple[str, list[str]]:
    """Weigh the signals into a machine-vs-human leaning and the reasons why."""
    machine = 0
    human = 0
    notes: list[str] = []

    if metrics is None:
        return "no data", ["no downloads recorded in the window"]

    if metrics.spike_share >= 0.5:
        machine += 1
        notes.append(
            f"{metrics.spike_share:.0%} of traffic is same-day spikes "
            f"(>= {metrics.spike_threshold}/day) — publish/mirror reactions, not steady use"
        )
    if FLAT_WEEK_LO <= metrics.weekend_weekday_ratio <= FLAT_WEEK_HI:
        machine += 1
        notes.append(
            f"flat week: weekend/weekday ratio {metrics.weekend_weekday_ratio:.2f} "
            "(~1.0) — automated traffic ignores weekends"
        )
    elif 0 < metrics.weekend_weekday_ratio < HUMAN_WEEKDAY_RATIO:
        human += 1
        notes.append(
            f"weekday-skewed: weekend/weekday ratio {metrics.weekend_weekday_ratio:.2f} "
            "(< 0.7) — consistent with humans installing at work"
        )
    if metrics.zero_days > 0:
        machine += 1
        notes.append(
            f"{metrics.zero_days} zero-download day(s) in the active window — "
            "no persistent human floor across timezones"
        )

    if versions is not None:
        if versions.prerelease_versions > 0:
            machine += 1
            notes.append(
                f"{versions.prerelease_versions} pre-release version(s) still drawing "
                "downloads — mirrors cloning the whole history, not humans"
            )
        if versions.top_share < 0.5:
            machine += 1
            notes.append(
                f"top version only {versions.top_share:.0%} of weekly downloads "
                "(smeared across the version history) — mirror fingerprint"
            )
        else:
            human += 1
            notes.append(
                f"downloads concentrate on {versions.top_version} "
                f"({versions.top_share:.0%}) — installs target the latest release"
            )

    if mirror_fraction is not None:
        if mirror_fraction >= 0.5:
            machine += 1
            notes.append(
                f"{mirror_fraction:.0%} of PyPI downloads are mirror traffic "
                "(stripped from the human analysis above)"
            )
        else:
            notes.append(f"{mirror_fraction:.0%} of PyPI downloads are mirror traffic")

    if machine > human:
        label = "machine-dominated (mirrors / CI / scanners)"
    elif human > machine:
        label = "human-leaning — investigate, this may be a real adopter"
    else:
        label = "mixed / inconclusive"
    return label, notes


@dataclass
class ReleaseMetrics:
    """GitHub Release asset download shape (the Homebrew / binary install path)."""

    total_downloads: int
    by_platform: dict[str, int]  # darwin / linux / windows / other
    desktop_downloads: int  # darwin + windows
    server_downloads: int  # linux
    desktop_fraction: float
    by_module: dict[str, int]


def parse_asset_platform(name: str) -> str | None:
    """Platform an asset targets, or None for non-binary assets (checksums, sigs)."""
    lowered = name.lower()
    if any(lowered.endswith(ext) for ext in (".txt", ".sig", ".pem", ".sbom", ".json")):
        return None
    if "darwin" in lowered or "macos" in lowered:
        return "darwin"
    if "linux" in lowered:
        return "linux"
    if "windows" in lowered:
        return "windows"
    return None


def _asset_module(name: str) -> str:
    """Module an asset belongs to: the name before the first version segment."""
    return re.split(r"_v?\d", name, maxsplit=1)[0] or name


def classify_release_assets(assets: list[tuple[str, int]]) -> ReleaseMetrics | None:
    """Aggregate per-asset download counts by platform and module.

    ``assets`` is a flat ``(asset_name, download_count)`` list across releases.
    Non-binary assets (checksums, signatures) are ignored. Returns ``None`` if no
    binary asset has ever been downloaded.
    """
    by_platform: dict[str, int] = {}
    by_module: dict[str, int] = {}
    for name, count in assets:
        platform = parse_asset_platform(name)
        if platform is None or count <= 0:
            continue
        by_platform[platform] = by_platform.get(platform, 0) + count
        by_module[_asset_module(name)] = by_module.get(_asset_module(name), 0) + count

    total = sum(by_platform.values())
    if total == 0:
        return None
    desktop = by_platform.get("darwin", 0) + by_platform.get("windows", 0)
    server = by_platform.get("linux", 0)
    return ReleaseMetrics(
        total_downloads=total,
        by_platform=by_platform,
        desktop_downloads=desktop,
        server_downloads=server,
        desktop_fraction=desktop / total,
        by_module=by_module,
    )


def verdict_release(metrics: ReleaseMetrics | None) -> tuple[str, list[str]]:
    """Lean on the desktop-vs-Linux split: desktop installs are humans, Linux is CI."""
    if metrics is None:
        return "no data", ["no release binaries downloaded yet"]
    notes = [
        f"{metrics.total_downloads} binary download(s): "
        + ", ".join(f"{p} {n}" for p, n in sorted(metrics.by_platform.items()))
    ]
    if metrics.desktop_fraction >= DESKTOP_FRACTION_HUMAN:
        label = "human-leaning — desktop installs (likely Homebrew on laptops)"
        notes.append(
            f"{metrics.desktop_fraction:.0%} of downloads are desktop (macOS/Windows) "
            f"with {metrics.server_downloads} Linux — release binaries aren't "
            "mirror-amplified, so this is real install activity, not CI or scanners"
        )
    elif metrics.server_downloads > metrics.desktop_downloads:
        label = "Linux-dominated — likely CI / containers"
        notes.append(
            f"{metrics.server_downloads} Linux vs {metrics.desktop_downloads} desktop "
            "downloads — automation territory"
        )
    else:
        label = "mixed / inconclusive"
    return label, notes


# ---------------------------------------------------------------------------
# Fetchers (best-effort I/O)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310 (https only)
        return resp.read()


def _get_json(url: str) -> dict:
    return json.loads(_get(url))


def _npm_encode(pkg: str) -> str:
    return urllib.parse.quote(pkg, safe="@")


def npm_daily(pkg: str) -> list[tuple[datetime.date, int]]:
    data = _get_json(f"https://api.npmjs.org/downloads/range/last-year/{_npm_encode(pkg)}")
    return [
        (datetime.date.fromisoformat(row["day"]), int(row["downloads"]))
        for row in data.get("downloads", [])
    ]


def npm_versions(pkg: str) -> dict[str, int]:
    data = _get_json(f"https://api.npmjs.org/versions/{_npm_encode(pkg)}/last-week")
    return {v: int(n) for v, n in data.get("downloads", {}).items()}


def npm_publish_dates(pkg: str) -> list[datetime.date]:
    """Publish date of every version, via the npm CLI. Empty if npm is absent."""
    try:
        out = subprocess.run(
            ["npm", "view", pkg, "time", "--json"],
            capture_output=True,
            text=True,
            timeout=HTTP_TIMEOUT,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    times = json.loads(out) if out.strip() else {}
    dates = []
    for key, value in times.items():
        if key in ("created", "modified"):
            continue
        dates.append(datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).date())
    return sorted(dates)


def pypi_overall(pkg: str) -> tuple[list[tuple[datetime.date, int]], float]:
    """Daily ``without_mirrors`` series and the mirror fraction over the window.

    PyPI is the one ecosystem that hands you the mirror split directly, so we
    analyse the human (mirror-free) series and report what fraction was mirrors.
    """
    data = _get_json(f"https://pypistats.org/api/packages/{urllib.parse.quote(pkg)}/overall")
    without: dict[datetime.date, int] = {}
    with_total = 0
    without_total = 0
    for row in data.get("data", []):
        day = datetime.date.fromisoformat(row["date"])
        n = int(row["downloads"])
        if row["category"] == "without_mirrors":
            without[day] = without.get(day, 0) + n
            without_total += n
        elif row["category"] == "with_mirrors":
            with_total += n
    series = sorted(without.items())
    mirror_fraction = ((with_total - without_total) / with_total) if with_total else 0.0
    return series, mirror_fraction


def go_imported_by(module: str) -> int | None:
    """Imported-by count from pkg.go.dev, or None if it can't be parsed."""
    try:
        html = _get(f"https://pkg.go.dev/{module}?tab=importedby").decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError):
        return None
    m = re.search(r"Imported By\s*<[^>]*>\s*([\d,]+)", html)
    if not m:
        m = re.search(r"([\d,]+)\s*packages? import", html)
    return int(m.group(1).replace(",", "")) if m else None


def github_release_assets(repo: str) -> list[tuple[str, int]]:
    """Every release asset's (name, download_count) for a repo, across all pages.

    Uses the public REST API. A GITHUB_TOKEN / GH_TOKEN in the environment raises
    the rate limit but is not required for a public repo.
    """
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    assets: list[tuple[str, int]] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        )
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            batch = json.loads(resp.read())
        if not batch:
            break
        for release in batch:
            for asset in release.get("assets", []):
                assets.append((asset["name"], int(asset["download_count"])))
        if len(batch) < 100:
            break
        page += 1
    return assets


# ---------------------------------------------------------------------------
# Reporting


def _print_series_block(metrics: SeriesMetrics) -> None:
    print(
        f"    window {metrics.active_days}d | total {metrics.total} | "
        f"spikes {metrics.spike_days}d = {metrics.spike_share:.0%} of traffic "
        f"(>= {metrics.spike_threshold}/day)"
    )
    print(
        f"    baseline median {metrics.baseline_median:.0f}/day, "
        f"{metrics.zero_days} zero-day(s) | "
        f"weekday {metrics.weekday_per_day:.1f}/day vs weekend "
        f"{metrics.weekend_per_day:.1f}/day (ratio {metrics.weekend_weekday_ratio:.2f})"
    )


def _print_verdict(label: str, notes: list[str]) -> None:
    print(f"    VERDICT: {label}")
    for n in notes:
        print(f"      - {n}")


def report_npm(pkg: str) -> dict:
    print(f"\nnpm  {pkg}")
    try:
        series = npm_daily(pkg)
        versions = npm_versions(pkg)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"package": pkg, "ecosystem": "npm", "error": str(exc)}

    metrics = classify_series(series)
    vmetrics = classify_versions(versions)
    label, notes = verdict(metrics, vmetrics)

    if metrics:
        _print_series_block(metrics)
    if vmetrics:
        print(
            f"    versions: {vmetrics.versions_with_downloads} drawing downloads, "
            f"{vmetrics.prerelease_versions} pre-release; "
            f"top {vmetrics.top_version} = {vmetrics.top_share:.0%}"
        )
    publishes = npm_publish_dates(pkg)
    if publishes and metrics:
        print(f"    {len(publishes)} published version(s); cross-check spike days against these")
    _print_verdict(label, notes)
    return {
        "package": pkg,
        "ecosystem": "npm",
        "metrics": asdict(metrics) if metrics else None,
        "versions": asdict(vmetrics) if vmetrics else None,
        "verdict": label,
        "notes": notes,
    }


def report_pypi(pkg: str) -> dict:
    print(f"\nPyPI {pkg}")
    try:
        series, mirror_fraction = pypi_overall(pkg)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"package": pkg, "ecosystem": "pypi", "error": str(exc)}

    metrics = classify_series(series)
    label, notes = verdict(metrics, None, mirror_fraction)
    if metrics:
        _print_series_block(metrics)
    print(f"    mirror traffic: {mirror_fraction:.0%} (excluded from the analysis above)")
    _print_verdict(label, notes)
    return {
        "package": pkg,
        "ecosystem": "pypi",
        "metrics": asdict(metrics) if metrics else None,
        "mirror_fraction": mirror_fraction,
        "verdict": label,
        "notes": notes,
    }


def report_go(module: str) -> dict:
    print(f"\nGo   {module}")
    count = go_imported_by(module)
    if count is None:
        print("    imported-by: unavailable (parse failed or offline)")
    else:
        print(f"    imported-by (pkg.go.dev): {count}")
    print(
        "    Go publishes no download counts; adoption-by-reference only. "
        f"Also check: https://pkg.go.dev/{module}?tab=importedby"
    )
    print(f"    and GitHub dependents: https://github.com/{GITHUB_REPO}/network/dependents")
    return {"module": module, "ecosystem": "go", "imported_by": count}


def report_github_releases(repo: str) -> dict:
    print(f"\nHomebrew / GitHub Releases  {repo}")
    try:
        assets = github_release_assets(repo)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"    unavailable: {exc}")
        return {"repo": repo, "ecosystem": "github-releases", "error": str(exc)}

    metrics = classify_release_assets(assets)
    label, notes = verdict_release(metrics)
    if metrics:
        top = sorted(metrics.by_module.items(), key=lambda kv: kv[1], reverse=True)
        print("    by module: " + ", ".join(f"{m} {n}" for m, n in top))
    _print_verdict(label, notes)
    print(
        "    note: counts are cumulative per release (no daily series), and a custom "
        "Homebrew tap gets no formulae.brew.sh analytics — this asset count is the signal."
    )
    return {
        "repo": repo,
        "ecosystem": "github-releases",
        "metrics": asdict(metrics) if metrics else None,
        "verdict": label,
        "notes": notes,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--npm", nargs="*", metavar="PKG")
    parser.add_argument("--pypi", nargs="*", metavar="PKG")
    parser.add_argument("--go", nargs="*", metavar="MODULE")
    parser.add_argument("--github", metavar="OWNER/REPO", help="repo for release-asset counts")
    parser.add_argument("--no-npm", action="store_true")
    parser.add_argument("--no-pypi", action="store_true")
    parser.add_argument("--go-off", action="store_true")
    parser.add_argument("--no-github", action="store_true")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)

    npm_pkgs = args.npm if args.npm is not None else NPM_PACKAGES
    pypi_pkgs = args.pypi if args.pypi is not None else PYPI_PACKAGES
    go_mods = args.go if args.go is not None else GO_MODULES
    gh_repo = args.github if args.github is not None else GITHUB_REPO

    results = []
    if not args.no_npm:
        for pkg in npm_pkgs:
            results.append(report_npm(pkg))
    if not args.no_pypi:
        for pkg in pypi_pkgs:
            results.append(report_pypi(pkg))
    if not args.go_off:
        for mod in go_mods:
            results.append(report_go(mod))
    if not args.no_github:
        results.append(report_github_releases(gh_repo))

    if args.json:
        print("\n" + json.dumps(results, indent=2, default=str))
    print(
        "\nReminder: a 'machine-dominated' verdict is the expected baseline for a "
        "young package. Watch for the shape to change — a sustained, weekday-skewed "
        "baseline climbing on the latest version is your first real adopter."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
