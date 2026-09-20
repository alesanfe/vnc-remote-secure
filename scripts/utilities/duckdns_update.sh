#!/bin/bash
# ============================================================================
# Duck DNS Update Script
# ============================================================================
# DEPRECATED legacy fallback — the canonical implementation is the
# Python script scripts/utilities/duckdns_update.py (used by
# `make duckdns-update` / `duckdns-daemon` / `duckdns-check`).
# This Bash version is retained for environments without Python.
#
# Updates the IP address for a Duck DNS domain.
# Works on both Linux and Windows (Git Bash / MSYS2).
#
# Usage:
#   ./scripts/utilities/duckdns_update.sh          # One-shot update
#   ./scripts/utilities/duckdns_update.sh --daemon # Continuous update (every N minutes)
#   ./scripts/utilities/duckdns_update.sh --check  # Check current DNS resolution
#
# Required environment variables (from .env):
#   DUCK_DOMAIN      - Duck DNS subdomain (e.g. "alesanfe" for alesanfe.duckdns.org)
#   DUCKDNS_TOKEN    - Duck DNS API token
#
# Optional:
#   DUCKDNS_UPDATE_INTERVAL - Update interval in minutes (default: 5)
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load .env if it exists
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

# Validate required variables
if [[ -z "${DUCK_DOMAIN:-}" ]]; then
    echo -e "${RED}Error: DUCK_DOMAIN not set. Configure it in .env${NC}"
    echo -e "${YELLOW}  Example: DUCK_DOMAIN=alesanfe${NC}"
    exit 1
fi

if [[ -z "${DUCKDNS_TOKEN:-}" ]]; then
    echo -e "${RED}Error: DUCKDNS_TOKEN not set. Configure it in .env${NC}"
    echo -e "${YELLOW}  Get your token from https://www.duckdns.org/${NC}"
    exit 1
fi

# Duck DNS API endpoint
DUCKDNS_API="https://www.duckdns.org/update"

# Strip .duckdns.org suffix if user included it
DUCK_DOMAIN="${DUCK_DOMAIN%.duckdns.org}"
DUCK_DOMAIN="${DUCK_DOMAIN%.duckdns.org}"

# Strict charset validation: the domain is interpolated into curl
# config files and Python -c strings below — anything outside the
# DuckDNS naming set ([a-z0-9-]) could break quoting or inject into
# those contexts. Fail fast instead.
if [[ ! "$DUCK_DOMAIN" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$ ]]; then
    echo -e "${RED}Error: DUCK_DOMAIN contains invalid characters: '${DUCK_DOMAIN}'${NC}"
    echo -e "${YELLOW}  Expected: lowercase letters, digits, hyphens (e.g. alesanfe)${NC}"
    exit 1
fi

# Interval for daemon mode (in seconds)
INTERVAL_SECONDS=$((${DUCKDNS_UPDATE_INTERVAL:-5} * 60))

# ============================================================================
# Functions
# ============================================================================

update_ip() {
    # Duck DNS API: empty ip= means auto-detect client IP
    local response
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if command -v curl &>/dev/null; then
        # The token must not appear in the process argv — it would be
        # visible to any local user via /proc/<pid>/cmdline (ps). Read
        # the full URL from a stdin config file instead.
        response=$(curl -sS --max-time 30 --config - <<EOF 2>&1
url = "${DUCKDNS_API}?domains=${DUCK_DOMAIN}&token=${DUCKDNS_TOKEN}&ip="
EOF
)
    elif command -v wget &>/dev/null; then
        # wget has no stdin-config equivalent; fall back to the Python
        # path below, which keeps the token out of the process table.
        # Domain is charset-validated above; the token reaches Python via
    # the environment (never interpolated into the -c source, so a
    # quote in it cannot inject).
    response=$(DUCKDNS_API_URL="$DUCKDNS_API" python3 -c "
import os, urllib.request
url = '%s?domains=%s&token=%s&ip=' % (
    os.environ['DUCKDNS_API_URL'],
    os.environ['DUCK_DOMAIN'],
    os.environ['DUCKDNS_TOKEN'])
try:
    with urllib.request.urlopen(url, timeout=30) as r:
        print(r.read().decode().strip())
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1)
    else
        # Fallback to Python (available on both platforms)
        # Domain is charset-validated above; the token reaches Python via
    # the environment (never interpolated into the -c source, so a
    # quote in it cannot inject).
    response=$(DUCKDNS_API_URL="$DUCKDNS_API" python3 -c "
import os, urllib.request
url = '%s?domains=%s&token=%s&ip=' % (
    os.environ['DUCKDNS_API_URL'],
    os.environ['DUCK_DOMAIN'],
    os.environ['DUCKDNS_TOKEN'])
try:
    with urllib.request.urlopen(url, timeout=30) as r:
        print(r.read().decode().strip())
except Exception as e:
    print(f'ERROR: {e}')
" 2>&1)
    fi

    if [[ "$response" == "OK" ]]; then
        echo -e "${GREEN}[${timestamp}] Duck DNS updated: ${DUCK_DOMAIN}.duckdns.org${NC}"
        return 0
    elif [[ "$response" == "ko" ]]; then
        echo -e "${RED}[${timestamp}] Duck DNS update FAILED (invalid token or domain)${NC}"
        return 1
    else
        echo -e "${RED}[${timestamp}] Duck DNS update error: ${response}${NC}"
        return 1
    fi
}

check_dns() {
    echo -e "${BLUE}Checking DNS resolution for ${DUCK_DOMAIN}.duckdns.org...${NC}"

    local resolved_ip
    if command -v dig &>/dev/null; then
        resolved_ip=$(dig +short "${DUCK_DOMAIN}.duckdns.org" A 2>/dev/null | head -1)
    elif command -v nslookup &>/dev/null; then
        resolved_ip=$(nslookup "${DUCK_DOMAIN}.duckdns.org" 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}' | head -1)
    elif command -v host &>/dev/null; then
        resolved_ip=$(host "${DUCK_DOMAIN}.duckdns.org" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -1)
    else
        # Python fallback
        resolved_ip=$(python3 -c "
import os, socket
try:
    print(socket.gethostbyname(os.environ['DUCK_DOMAIN'] + '.duckdns.org'))
except Exception:
    print('ERROR')
" 2>&1)
    fi

    if [[ -n "$resolved_ip" && "$resolved_ip" != "ERROR" ]]; then
        echo -e "${GREEN}  ${DUCK_DOMAIN}.duckdns.org -> ${resolved_ip}${NC}"

        # Get current public IP
        local public_ip
        if command -v curl &>/dev/null; then
            public_ip=$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null)
        else
            public_ip=$(python3 -c "
import urllib.request
try:
    with urllib.request.urlopen('https://api.ipify.org', timeout=10) as r:
        print(r.read().decode().strip())
except Exception:
    print('ERROR')
" 2>&1)
        fi

        if [[ -n "$public_ip" && "$public_ip" != "ERROR" ]]; then
            echo -e "${BLUE}  Current public IP: ${public_ip}${NC}"
            if [[ "$resolved_ip" == "$public_ip" ]]; then
                echo -e "${GREEN}  ✓ DNS is up to date${NC}"
            else
                echo -e "${YELLOW}  ⚠ DNS is stale (resolved: ${resolved_ip}, current: ${public_ip})${NC}"
                echo -e "${YELLOW}    Run 'make duckdns-update' to fix.${NC}"
            fi
        fi
    else
        echo -e "${RED}  Could not resolve ${DUCK_DOMAIN}.duckdns.org${NC}"
        return 1
    fi
}

show_status() {
    echo -e "${BLUE}Duck DNS Configuration:${NC}"
    echo "  Domain:     ${DUCK_DOMAIN}.duckdns.org"
    # Never echo token fragments — 12 of ~32 chars is enough material
    # to cut brute-force cost dramatically if a log leaks.
    echo "  Token:      *** (${#DUCKDNS_TOKEN} chars)"
    echo "  Interval:   ${DUCKDNS_UPDATE_INTERVAL:-5} minutes"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

case "${1:-}" in
    --daemon|-d)
        show_status
        echo -e "${BLUE}Starting daemon mode (update every ${DUCKDNS_UPDATE_INTERVAL:-5} min)...${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop.${NC}"
        echo ""
        # Update immediately, then on interval
        update_ip || true
        while true; do
            sleep "$INTERVAL_SECONDS"
            update_ip || true
        done
        ;;
    --check|-c)
        check_dns
        ;;
    --help|-h)
        echo "Duck DNS Update Script"
        echo ""
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  (none)     One-shot IP update"
        echo "  --daemon   Continuous update (every ${DUCKDNS_UPDATE_INTERVAL:-5} min)"
        echo "  --check    Check current DNS resolution"
        echo "  --help     Show this help"
        ;;
    *)
        show_status
        update_ip
        ;;
esac
