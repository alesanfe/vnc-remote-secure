#!/usr/bin/env bash
# Format code (Linux)
set -euo pipefail

echo "=== Formatting code ==="

# Python formatting
if command -v black &>/dev/null; then
    echo "Running black..."
    black src/vnc_remote_secure/ tests/ tools/ scripts/utilities/ 2>/dev/null || true
fi

if command -v ruff &>/dev/null; then
    echo "Running ruff --fix..."
    ruff check --fix src/vnc_remote_secure/ tests/ tools/ 2>/dev/null || true
fi

# Shell formatting
if command -v shfmt &>/dev/null; then
    echo "Running shfmt..."
    shfmt -w -i 4 src/ scripts/ 2>/dev/null || true
fi

echo "Formatting complete."
