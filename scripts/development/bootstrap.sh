#!/usr/bin/env bash
# Bootstrap development environment for VNC Remote Secure (Linux)
set -euo pipefail

echo "=== VNC Remote Secure - Development Bootstrap ==="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate and install
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

# Install pre-commit hooks
if command -v pre-commit &>/dev/null; then
    pre-commit install
    echo "Pre-commit hooks installed."
fi

echo ""
echo "Development environment ready."
echo "Activate with: source .venv/bin/activate"
