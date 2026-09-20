#!/bin/bash
# ============================================================================
# RESTORE SCRIPT — thin compatibility wrapper
# ============================================================================
# DEPRECATED: retained for backward compatibility. The canonical restore
# implementation is the Python CLI:
#
#     vnc-remote restore <backup_file.tar.gz>
#
# This script forwards all arguments to `vnc-remote restore`.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Prefer THIS checkout's wrapper/Python over a system-installed
# vnc-remote — the installed CLI points at /opt, not at this tree.
if [[ -x "$PROJECT_DIR/vnc-remote" ]]; then
    exec "$PROJECT_DIR/vnc-remote" restore "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m vnc_remote_secure.cli restore "$@"
elif command -v vnc-remote >/dev/null 2>&1; then
    exec vnc-remote restore "$@"
else
    exec python -m vnc_remote_secure.cli restore "$@"
fi
