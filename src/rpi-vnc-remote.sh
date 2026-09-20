#!/bin/bash
# ============================================================================
# rpi-vnc-remote.sh — Legacy Bash entry point (thin delegator)
# ============================================================================
# This script is retained for backward compatibility. All functionality
# is implemented in the canonical Python CLI (vnc_remote_secure.cli).
# This file only maps the legacy Bash command names to the Python
# subcommands and delegates.
#
# Usage:
#   src/rpi-vnc-remote.sh [setup|start|stop|restart|status|help] [--no-ssl]
#
# Legacy command mapping:
#   setup   → install + start  (full installation and service startup)
#   start   → start
#   stop    → stop
#   restart → restart
#   status  → status
#   help    → help
# ============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# Get script directory and project root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
export PROJECT_DIR
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Resolve a Python interpreter.
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "Error: Python interpreter not found" >&2
    exit 1
fi

# Parse the legacy command and map it to the Python CLI subcommand.
CMD="${1:-setup}"
shift 2>/dev/null || true

# Collect flags to forward (e.g. --no-ssl).
FORWARD_FLAGS=()
for arg in "$@"; do
    case "$arg" in
        --no-ssl)
            FORWARD_FLAGS+=("--no-ssl")
            ;;
        --verbose|-v)
            FORWARD_FLAGS+=("--verbose")
            ;;
        --json)
            FORWARD_FLAGS+=("--json")
            ;;
        --dry-run)
            FORWARD_FLAGS+=("--dry-run")
            ;;
        *)
            FORWARD_FLAGS+=("$arg")
            ;;
    esac
done

case "$CMD" in
    setup)
        # Legacy 'setup' = full install + start.
        # --no-ssl is a start-time flag: the 'install' subcommand does
        # not accept it, so it must not be forwarded there.
        INSTALL_FLAGS=()
        for arg in "${FORWARD_FLAGS[@]}"; do
            [ "$arg" = "--no-ssl" ] || INSTALL_FLAGS+=("$arg")
        done
        "$PY" -m vnc_remote_secure.cli install "${INSTALL_FLAGS[@]}" \
            && exec "$PY" -m vnc_remote_secure.cli start "${FORWARD_FLAGS[@]}"
        ;;
    start)
        exec "$PY" -m vnc_remote_secure.cli start "${FORWARD_FLAGS[@]}"
        ;;
    stop)
        exec "$PY" -m vnc_remote_secure.cli stop "${FORWARD_FLAGS[@]}"
        ;;
    restart)
        exec "$PY" -m vnc_remote_secure.cli restart "${FORWARD_FLAGS[@]}"
        ;;
    status)
        exec "$PY" -m vnc_remote_secure.cli status "${FORWARD_FLAGS[@]}"
        ;;
    help|--help|-h)
        exec "$PY" -m vnc_remote_secure.cli help
        ;;
    *)
        # Pass through any other command to the canonical CLI — it
        # accepts doctor, install, uninstall, backup, restore, session,
        # secrets, config, service and version. Rejecting them here
        # would break documented commands for users of this legacy
        # entry point; the CLI prints the authoritative error for
        # genuinely unknown names.
        exec "$PY" -m vnc_remote_secure.cli "$CMD" "${FORWARD_FLAGS[@]}"
        ;;
esac
