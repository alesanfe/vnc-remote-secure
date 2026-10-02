#!/usr/bin/env python3
"""Technical-debt signal audit — repeatable, read-only.

Runs the automatable parts of the debt-detection methodology:

- debt markers (TODO/FIXME/HACK/XXX/WORKAROUND/DEPRECATED)
- largest files (LOC)
- radon cyclomatic-complexity top offenders
- git hotspots: churn (6-month commit frequency) x complexity
- co-change pairs: files committed together suspiciously often
- disabled tests: skip / skipif / xfail markers
- dead code: vulture (confidence >= 80)
- config drift: schema keys missing from .env.example

Usage:
    python tools/debt_audit.py [--since "6 months ago"] [--top 15]

Nothing here writes findings into docs/tech-debt.md — triage is a
human/agent decision; this tool just surfaces the signals.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "vnc_remote_secure"
TESTS = ROOT / "tests"

MARKERS = re.compile(r"\b(TODO|FIXME|HACK|XXX|WORKAROUND|TEMP|DEPRECATED|REMOVE LATER|QUICK FIX)\b")


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        return ""


def _py_files(base: Path) -> list[Path]:
    return [
        p for p in base.rglob("*.py") if "__pycache__" not in p.parts and ".venv" not in p.parts
    ]


def scan_markers() -> dict[str, int]:
    counts: dict[str, int] = collections.Counter()
    for p in _py_files(SRC):
        try:
            for m in MARKERS.finditer(p.read_text(encoding="utf-8", errors="replace")):
                counts[m.group(1)] += 1
        except OSError:
            pass
    return dict(counts)


def largest_files(top: int) -> list[tuple[int, str]]:
    sizes = []
    for p in _py_files(SRC):
        try:
            sizes.append(
                (
                    len(p.read_text(encoding="utf-8", errors="replace").splitlines()),
                    str(p.relative_to(ROOT)),
                )
            )
        except OSError:
            pass
    return sorted(sizes, reverse=True)[:top]


def _radon_by_file() -> dict[str, int]:
    """file -> max CC across its blocks (radon `cc -s` output)."""
    out = _run([sys.executable, "-m", "radon", "cc", "-s", "-o", "nc", str(SRC)])
    worst: dict[str, int] = {}
    cur = None
    for line in out.splitlines():
        line = line.rstrip()
        if line.endswith(".py"):
            cur = line.strip()
            continue
        m = re.search(r"-\s*[A-Z]?\s*\((\d+)\)", line)
        if cur and m:
            worst[cur] = max(worst.get(cur, 0), int(m.group(1)))
    return worst


def _is_source(path: str) -> bool:
    """Filter built artifacts from git churn — hashed SPA bundles under
    web/static/admin/assets/ commit constantly and are not source."""
    return path.endswith(".py") and "web/static/" not in path.replace("\\", "/")


def _churn(since: str) -> dict[str, int]:
    """file -> number of commits touching it."""
    out = _run(
        ["git", "log", f"--since={since}", "--name-only", "--format=%H", "--", "src/", "tests/"]
    )
    churn: dict[str, int] = collections.Counter()
    for line in out.splitlines():
        line = line.strip()
        if not line or re.fullmatch(r"[0-9a-f]{40}", line) or not _is_source(line):
            continue
        churn[line] += 1
    return churn


def hotspots(since: str, top: int) -> list[tuple[float, int, int, str]]:
    """(score, churn, max_cc, file) — churn x complexity."""
    import os

    cc = _radon_by_file()
    churn = _churn(since)
    rows = []
    for f, c in churn.items():
        # git reports /-separated repo-relative paths; radon gets the
        # absolute SRC root — normalize before joining.
        abs_f = str(ROOT / f.replace("/", os.sep))
        cc_f = cc.get(abs_f)
        if cc_f and c >= 3:
            rows.append((round(c * cc_f, 1), c, cc_f, f))
    return sorted(rows, reverse=True)[:top]


def co_change(since: str, top: int) -> list[tuple[int, str, str]]:
    """Pairs of files that appear in the same commits most often —
    hidden coupling signal (keep only pairs in different dirs)."""
    out = _run(["git", "log", f"--since={since}", "--name-only", "--format=%H", "--", "src/"])
    pairs: dict[tuple[str, str], int] = collections.Counter()
    files_in_commit: list[str] = []
    for line in out.splitlines() + ["0123456789abcdef0123456789abcdef01234567"]:
        line = line.strip()
        if re.fullmatch(r"[0-9a-f]{40}", line):
            uniq = sorted({f for f in files_in_commit if _is_source(f)})
            for i in range(len(uniq)):
                for j in range(i + 1, len(uniq)):
                    if Path(uniq[i]).parent != Path(uniq[j]).parent:
                        pairs[(uniq[i], uniq[j])] += 1
            files_in_commit = []
        elif line:
            files_in_commit.append(line)
    return [(n, a, b) for (a, b), n in sorted(pairs.items(), key=lambda kv: -kv[1]) if n >= 8][:top]


def disabled_tests() -> dict[str, int]:
    counts: dict[str, int] = collections.Counter()
    pat = re.compile(r"pytest\.mark\.(skip|skipif|xfail)|@(unittest\.)?skip")
    for p in _py_files(TESTS):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pat.finditer(text):
            key = m.group(1) or "skip"
            counts[key] += 1
    return dict(counts)


def dead_code() -> list[str]:
    """vulture at confidence >= 80 — high-precision only."""
    # Whitelist = a .py file scanned alongside the sources: names used
    # there count as used (compat signatures, protocol params).
    wl = ROOT / "tools" / "vulture_whitelist.py"
    cmd = [sys.executable, "-m", "vulture", str(SRC), "--min-confidence", "80"]
    if wl.exists():
        cmd.insert(4, str(wl))
    out = _run(cmd)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return lines[:40]


def schema_env_drift() -> list[str]:
    """Schema-documented env vars absent from .env.example —
    undocumented-knob debt (some are legitimately internal, but the
    list should be a conscious decision, not an accident)."""
    schema = ROOT / "src" / "vnc_remote_secure" / "config" / "schema" / "config.schema.json"
    env_ex = ROOT / ".env.example"
    if not schema.exists() or not env_ex.exists():
        return []
    keys = set(json.loads(schema.read_text(encoding="utf-8")).get("properties", {}))
    example = {
        ln.split("=", 1)[0].strip().lstrip("#").strip()
        for ln in env_ex.read_text(encoding="utf-8", errors="replace").splitlines()
        if "=" in ln
    }
    return sorted(keys - example)


def section(title: str) -> None:
    print(f"\n{'=' * 10} {title} {'=' * (60 - len(title))}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--since", default="6 months ago")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    section("DEBT MARKERS")
    m = scan_markers()
    print(dict(sorted(m.items(), key=lambda kv: -kv[1])) or "none")

    section("LARGEST FILES (LOC)")
    for size, f in largest_files(args.top):
        print(f"{size:6d}  {f}")

    section(f"HOTSPOTS — churn x max-CC (since {args.since})")
    for score, churn, cc, f in hotspots(args.since, args.top):
        print(f"{score:7.1f}  churn={churn:3d}  cc={cc:2d}  {f}")

    section("CO-CHANGE PAIRS (hidden coupling)")
    for n, a, b in co_change(args.since, args.top):
        print(f"{n:3d}  {a}  +  {b}")

    section("DISABLED TESTS")
    print(disabled_tests() or "none")

    section("DEAD CODE (vulture >=80)")
    for line in dead_code():
        print(f"  {line}")

    section("SCHEMA VARS NOT IN .env.example")
    for k in schema_env_drift():
        print(f"  {k}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
