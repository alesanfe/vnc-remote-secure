#!/bin/bash
# ============================================================================
# Level 0: static analysis — shell syntax, CRLF, shellcheck, Python syntax
# ============================================================================
# The testing pyramid advertises this level but it had no tests: the
# checks only ran via `make lint`. Keep a real, fast Level 0 so
# `run_tests.sh static/` actually verifies the tree.
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
failures=0

collect_sh() {
    find "$ROOT" -name '*.sh' -type f \
        -not -path '*/node_modules/*' \
        -not -path '*/.git/*' \
        -not -path '*/novnc/*' | sort
}

echo "[static] Checking shell script syntax (bash -n)..."
while IFS= read -r f; do
    if ! bash -n "$f" 2>/dev/null; then
        echo "  FAIL bash -n: ${f#$ROOT/}"
        bash -n "$f" 2>&1 | head -3
        failures=$((failures + 1))
    fi
done < <(collect_sh)

echo "[static] Checking for CRLF line endings in shell scripts..."
while IFS= read -r f; do
    if grep -q $'\r' "$f" 2>/dev/null; then
        echo "  FAIL CRLF: ${f#$ROOT/}"
        failures=$((failures + 1))
    fi
done < <(collect_sh)

# shellcheck may exist but be broken (e.g. an npm shim without node) —
# verify it can actually run before trusting its exit codes.
_shellcheck_ok() {
    command -v shellcheck >/dev/null 2>&1 && \
        shellcheck --version >/dev/null 2>&1
}

if _shellcheck_ok; then
    echo "[static] Running shellcheck (errors only)..."
    while IFS= read -r f; do
        if ! shellcheck -S error "$f" >/dev/null 2>&1; then
            echo "  FAIL shellcheck: ${f#$ROOT/}"
            shellcheck -S error "$f" 2>&1 | head -8
            failures=$((failures + 1))
        fi
    done < <(collect_sh)
else
    echo "[static] shellcheck not usable — skipping (install to enable)"
fi

echo "[static] Checking Python syntax (compileall)..."
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
if ! "$PY" -m compileall -q "$ROOT/src" 2>/dev/null; then
    echo "  FAIL Python syntax in src/"
    "$PY" -m compileall -q "$ROOT/src" 2>&1 | head -5
    failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
    echo "[static] All static checks passed"
    exit 0
else
    echo "[static] $failures failure(s)"
    exit 1
fi
