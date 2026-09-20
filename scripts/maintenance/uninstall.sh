#!/bin/bash
# ============================================================================
# UNINSTALLER — thin compatibility wrapper
# ============================================================================
# DEPRECATED: retained for backward compatibility. The canonical uninstaller
# is the Python CLI (src/vnc_remote_secure/core/uninstall.py):
#
#     vnc-remote uninstall                # remove all project changes
#     vnc-remote uninstall --keep-data    # keep SSL certs, data, backups
#
# The Python uninstaller is always non-interactive; the legacy --force/-f
# flag is accepted and ignored. This script forwards remaining arguments
# to `vnc-remote uninstall`.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Map legacy flags: --force/-f is a no-op (the Python uninstaller is
# non-interactive by design); everything else is forwarded.
forward_args=()
for arg in "$@"; do
    case "$arg" in
        --force|-f) ;;
        *) forward_args+=("$arg") ;;
    esac
done

# Prefer THIS checkout's wrapper/Python over a system-installed
# vnc-remote — the installed CLI points at /opt, not at this tree.
if [[ -x "$PROJECT_DIR/vnc-remote" ]]; then
    exec "$PROJECT_DIR/vnc-remote" uninstall "${forward_args[@]}"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m vnc_remote_secure.cli uninstall "${forward_args[@]}"
elif command -v vnc-remote >/dev/null 2>&1; then
    exec vnc-remote uninstall "${forward_args[@]}"
else
    exec python -m vnc_remote_secure.cli uninstall "${forward_args[@]}"
fi
