#!/bin/bash
# ============================================================================
# VNC Remote Secure - DEPRECATED launcher
#
# This script is DEPRECATED and no longer starts services directly. The
# canonical entry point is the unified Python CLI:
#
#     vnc-remote start
#
# which uses the service manager (vnc_remote_secure.core.service_manager)
# to start, track, and stop all services with proper locking, PID
# tracking, auth gateway enforcement, and security profile application.
#
# Keeping this file as a thin delegator preserves backward compatibility
# for operators who still call `./launch.sh`. It forwards all arguments
# to the unified CLI and exits.
# ============================================================================
set -e

cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
export PROJECT_DIR
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Forward to the unified Python CLI *of this checkout* — NOT a
# system-installed vnc-remote (which would point at /opt, not here).
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m vnc_remote_secure.cli "$@"
else
    exec python -m vnc_remote_secure.cli "$@"
fi
