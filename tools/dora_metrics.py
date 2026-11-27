#!/usr/bin/env python3
"""DORA metrics from git history (OBS-002 / TD-18).

Four DORA keys, computed with stdlib + `git log` only:

- Deployment frequency — annotated release tags (v*) per window.
- Lead time for changes — median(commit date → release tag that
  contains it), approximated per release window.
- Change failure rate — share of commits in a release window that are
  reverts/hotfixes (`revert`, `rollback`, `hotfix` in subject).
- Mean time to restore — for each revert commit, time between the
  reverted commit landing and the revert landing.

Git alone cannot see runtime incidents — CFR/MTTR are bounded proxies
(revert-driven). Extend with CI failure data when a workflow API is
available. Run: python tools/dora_metrics.py [--months 12] [--json].
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
from datetime import datetime, timezone

FAIL_RE = re.compile(r"\b(revert|rollback|hotfix)\b", re.IGNORECASE)
REVERTED_RE = re.compile(r"This reverts commit ([0-9a-f]{7,40})", re.IGNORECASE)


def _git(*args: str) -> list[str]:
    out = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    )
    return [ln for ln in out.stdout.splitlines() if ln]


def _tags() -> list[tuple[datetime, str]]:
    """Release tags sorted by tag date: [(date, name)]."""
    rows = _git("tag", "-l", "v*", "--format=%(creatordate:iso-strict) %(refname:short)")
    out = []
    for ln in rows:
        ts, name = ln.rsplit(" ", 1)
        out.append((datetime.fromisoformat(ts.strip()), name))
    return sorted(out)


def _window_commits(prev_tag: str | None, tag: str) -> list[tuple[datetime, str, str]]:
    """[(date, sha, subject)] in (prev_tag, tag] or full history if prev is None."""
    rng = f"{prev_tag}..{tag}" if prev_tag else tag
    out = []
    for ln in _git("log", rng, "--format=%cI|%H|%s"):
        iso, sha, subj = ln.split("|", 2)
        out.append((datetime.fromisoformat(iso), sha, subj))
    return out


def _commit_date(sha: str) -> datetime | None:
    try:
        return datetime.fromisoformat(_git("show", "-s", "--format=%cI", sha)[0])
    except subprocess.CalledProcessError:
        return None


def collect(months: int) -> dict:
    tags = _tags()
    if not tags:
        return {"releases": 0, "note": "no v* tags — DORA needs released history"}
    cutoff = datetime.now(timezone.utc).replace(
        year=datetime.now(timezone.utc).year
    )
    # months-ago cutoff (approx: subtract months by hand, clamp day)
    y, m = cutoff.year, cutoff.month - months
    while m <= 0:
        m += 12
        y -= 1
    cutoff = cutoff.replace(year=y, month=m)

    windows = []
    prev = None
    for tag_date, name in tags:
        commits = _window_commits(prev, name)
        if tag_date >= cutoff or not windows:
            windows.append(
                {
                    "tag": name,
                    "date": tag_date,
                    "commits": commits,
                    "failures": sum(1 for _, _, s in commits if FAIL_RE.search(s)),
                }
            )
        prev = name

    in_window = [w for w in windows if w["date"] >= cutoff]
    total_commits = sum(len(w["commits"]) for w in in_window)
    total_fails = sum(w["failures"] for w in in_window)

    lead_times = [
        (w["date"] - statistics.median(c[0] for c in w["commits"])).total_seconds()
        / 86400
        for w in in_window
        if w["commits"]
    ]

    # MTTR: revert body "This reverts commit <sha>" → reverted-date → revert-date.
    mttr = []
    for w in windows:
        for cdate, sha, _subj in w["commits"]:
            if not FAIL_RE.search(_subj):
                continue
            body = "\n".join(_git("show", "-s", "--format=%b", sha))
            m = REVERTED_RE.search(body)
            if m and (orig := _commit_date(m.group(1))):
                mttr.append((cdate - orig).total_seconds() / 3600)

    span_days = max(
        (in_window[-1]["date"] - in_window[0]["date"]).days, 1
    ) if len(in_window) > 1 else 30

    return {
        "window_months": months,
        "releases": len(in_window),
        "deploy_frequency_per_month": round(len(in_window) / (span_days / 30.44), 2),
        "lead_time_days_median": round(statistics.median(lead_times), 1)
        if lead_times
        else None,
        "change_failure_rate_pct": round(100 * total_fails / total_commits, 1)
        if total_commits
        else None,
        "mttr_hours_median": round(statistics.median(mttr), 1) if mttr else None,
        "reverts_observed": total_fails,
        "commits_in_window": total_commits,
        "per_release": [
            {
                "tag": w["tag"],
                "date": w["date"].date().isoformat(),
                "commits": len(w["commits"]),
                "failures": w["failures"],
            }
            for w in in_window
        ],
    }


def _fmt(metrics: dict) -> str:
    if metrics.get("releases", 0) == 0:
        return f"DORA: {metrics.get('note')}"
    lines = [
        f"DORA metrics — last {metrics['window_months']}mo "
        f"({metrics['releases']} releases, {metrics['commits_in_window']} commits)",
        f"  Deploy frequency      : {metrics['deploy_frequency_per_month']}/month",
        f"  Lead time (median)    : {metrics['lead_time_days_median']} d",
        f"  Change failure rate   : {metrics['change_failure_rate_pct']}% "
        f"({metrics['reverts_observed']} reverts/hotfixes)",
        f"  MTTR (median, revert) : {metrics['mttr_hours_median']} h"
        if metrics["mttr_hours_median"] is not None
        else "  MTTR (median, revert) : n/a (no revert bodies matched)",
        "",
        "  per release:",
    ]
    for r in metrics["per_release"]:
        lines.append(
            f"    {r['tag']:<16} {r['date']}  commits={r['commits']:<4} failures={r['failures']}"
        )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--months", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    metrics = collect(args.months)
    print(json.dumps(metrics, indent=2, default=str) if args.json else _fmt(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
