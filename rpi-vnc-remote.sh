#!/bin/bash
# ============================================================================
# ROOT WRAPPER SCRIPT
# ============================================================================
# This script provides backward compatibility and convenience by allowing
# execution from the project root without navigating to src/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_SCRIPT="$SCRIPT_DIR/src/rpi-vnc-remote.sh"

# Check if main script exists
if [ ! -f "$MAIN_SCRIPT" ]; then
    echo "Error: Main script not found at $MAIN_SCRIPT"
    exit 1
fi

# Execute main script with all arguments
exec bash "$MAIN_SCRIPT" "$@"
