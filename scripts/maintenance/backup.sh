#!/bin/bash
# ============================================================================
# BACKUP SCRIPT — thin compatibility wrapper
# ============================================================================
# DEPRECATED: retained for backward compatibility. The canonical backup
# implementation is the Python CLI:
#
#     vnc-remote backup          # create a backup
#     vnc-remote backup --list   # list available backups
#
# This script forwards all arguments to `vnc-remote backup`.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Prefer THIS checkout's wrapper/Python over a system-installed
# vnc-remote — the installed CLI points at /opt, not at this tree.
if [[ -x "$PROJECT_DIR/vnc-remote" ]]; then
    exec "$PROJECT_DIR/vnc-remote" backup "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m vnc_remote_secure.cli backup "$@"
elif command -v vnc-remote >/dev/null 2>&1; then
    exec vnc-remote backup "$@"
else
    exec python -m vnc_remote_secure.cli backup "$@"
fi
