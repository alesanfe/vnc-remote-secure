#!/usr/bin/env bash
# Build release artifacts (Linux)
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(python3 -c "from vnc_remote_secure import __version__; print(__version__)" 2>/dev/null || echo "0.0.0")
fi

echo "=== Building VNC Remote Secure v${VERSION} ==="

# Clean previous builds
rm -rf dist/ build/ *.egg-info src/*.egg-info

# Build Python package
python3 -m build

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
