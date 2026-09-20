#!/bin/bash
# ============================================================================
# HEALTH CHECK — thin compatibility wrapper
# ============================================================================
# DEPRECATED: retained for backward compatibility. The canonical health
# check is the Python CLI doctor (src/vnc_remote_secure/core/doctor.py),
# which validates configuration, directories, secrets, SSL certs,
# binaries, service status, ports, and firewall rules:
#
#     vnc-remote doctor            # full diagnostic
#     vnc-remote doctor --json     # machine-readable output
#     vnc-remote status            # live service status table
#
# This script forwards all arguments to `vnc-remote doctor`.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Prefer THIS checkout's wrapper/Python over a system-installed
# vnc-remote — the installed CLI points at /opt, not at this tree.
if [[ -x "$PROJECT_DIR/vnc-remote" ]]; then
    exec "$PROJECT_DIR/vnc-remote" doctor "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m vnc_remote_secure.cli doctor "$@"
elif command -v vnc-remote >/dev/null 2>&1; then
    exec vnc-remote doctor "$@"
else
    exec python -m vnc_remote_secure.cli doctor "$@"
fi
