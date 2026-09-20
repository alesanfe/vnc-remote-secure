#!/usr/bin/env bash
# Build release artifacts (Linux) — manual convenience wrapper.
# CI uses `python -m build` directly; this script adds checksum generation.
# Usage: bash scripts/release/build.sh [version]
set -euo pipefail

# Prefer `python` (Windows interpreter / venv) over `python3`; on Git
# Bash for Windows `python3` resolves to a WSL interpreter that lacks
# project tooling like `build`.
PY=python3
if command -v python >/dev/null 2>&1; then
    PY=python
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(PYTHONPATH="$(dirname "$0")/../../src" "$PY" -c \
        "from vnc_remote_secure import __version__; print(__version__)" \
        2>/dev/null || true)
fi
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Cannot determine version from Python package." >&2
    echo "Pass the version explicitly: $0 X.Y.Z" >&2
    exit 1
fi

echo "=== Building VNC Remote Secure v${VERSION} ==="

# Clean previous builds (best-effort: stale egg-info may be locked
# by an editable install — build regenerates it anyway)
rm -rf dist/ build/ *.egg-info src/*.egg-info 2>/dev/null || true

# Build Python package
"$PY" -m build

# Generate checksums
if [ -d dist/ ]; then
    cd dist/
    sha256sum * > SHA256SUMS.txt
    cd ..
    echo "Checksums generated: dist/SHA256SUMS.txt"
fi

echo ""
echo "Build complete. Artifacts in dist/"
ls -la dist/ 2>/dev/null || echo "(no artifacts)"
