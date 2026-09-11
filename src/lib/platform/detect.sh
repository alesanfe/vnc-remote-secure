#!/bin/bash
# shellcheck disable=SC1091
# ============================================================================
# OS DETECTION MODULE
# ============================================================================
# Detects the operating system and exports the OS_TYPE variable.
# Also provides helper functions used by platform-specific backends.
#
# OS_TYPE values:
#   "linux"   - Native Linux (Debian, Ubuntu, Raspberry Pi OS, etc.)
#   "windows" - Windows running under Git Bash / MSYS2 / MinGW
#   "macos"   - macOS (future support)
#   "wsl"     - Windows Subsystem for Linux (behaves like Linux)
#
# This module is sourced FIRST, before any other platform module, so that
# OS_TYPE is available to all subsequent code.
# ============================================================================

detect_os() {
    # Check if we're inside WSL (Windows Subsystem for Linux)
    # WSL has /proc/version mentioning microsoft
    if [[ -f /proc/version ]]; then
        if grep -qi microsoft /proc/version 2>/dev/null; then
            echo "wsl"
            return 0
        fi
    fi

    # Check OSTYPE (set by Bash)
    case "$OSTYPE" in
        linux*|linux-gnu)
            echo "linux"
            return 0
            ;;
        msys|msys2|mingw*|cygwin)
            echo "windows"
            return 0
            ;;
        darwin*)
            echo "macos"
            return 0
            ;;
        freebsd*)
            echo "freebsd"
            return 0
            ;;
    esac

    # Fallback: check uname
    if command -v uname &>/dev/null; then
        local kernel
        kernel=$(uname -s 2>/dev/null)
        case "$kernel" in
            Linux)   echo "linux";   return 0 ;;
            MINGW*|MSYS*|CYGWIN*)
                     echo "windows"; return 0 ;;
            Darwin)  echo "macos";   return 0 ;;
            FreeBSD) echo "freebsd"; return 0 ;;
        esac
    fi

    # Unknown OS — default to linux (best-effort)
    echo "linux"
}

# Detect and export OS_TYPE (only once)
if [[ -z "${OS_TYPE:-}" ]]; then
    export OS_TYPE
    OS_TYPE=$(detect_os)
fi

# Helper: are we on Windows (Git Bash/MSYS2)?
is_windows() {
    [[ "$OS_TYPE" == "windows" ]]
}

# Helper: are we on Linux (native or WSL)?
is_linux() {
    [[ "$OS_TYPE" == "linux" || "$OS_TYPE" == "wsl" ]]
}

# Helper: are we on macOS?
is_macos() {
    [[ "$OS_TYPE" == "macos" ]]
}

# Source the platform-specific backend
# This is called by rpi-vnc-remote.sh AFTER all other modules are loaded,
# so platform functions can override the Linux-specific ones.
load_platform_backend() {
    local platform_dir
    platform_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    case "$OS_TYPE" in
        windows)
            # shellcheck source=/dev/null
            source "$platform_dir/windows.sh"
            ;;
        linux|wsl)
            # Linux backend is the default (existing code).
            # No override needed — the modules already target Linux.
            # shellcheck source=/dev/null
            if [[ -f "$platform_dir/linux.sh" ]]; then
                source "$platform_dir/linux.sh"
            fi
            ;;
        macos)
            # shellcheck source=/dev/null
            if [[ -f "$platform_dir/macos.sh" ]]; then
                source "$platform_dir/macos.sh"
            fi
            ;;
        *)
            # Use fallback warning that works even if log_warn is not yet defined
            if command -v log_warn &>/dev/null; then
                log_warn "Unknown OS type '$OS_TYPE', using Linux defaults" "PLATFORM"
            else
                echo "Warning: Unknown OS type '$OS_TYPE', using Linux defaults" >&2
            fi
            ;;
    esac
}
