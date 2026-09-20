#!/bin/bash
# ============================================================================
# Shared helpers for maintenance scripts
# ============================================================================
# Source this file from scripts/maintenance/*.sh to reuse common helpers.
# Usage: source "$(dirname "$0")/common.sh"
# ============================================================================

# Ask for confirmation. Returns 0 if yes, 1 if no.
confirm_action() {
    local message="$1"
    read -p "$message (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}
