#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# DISPLAY AND UI UTILITIES
# ============================================================================

print_section() {
    local title="$1"
    echo ""
    echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[1;34m  ${title}\033[0m"
    echo -e "\033[1;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

print_separator() {
    echo -e "\033[0;90m────────────────────────────────────────────────────────────\033[0m"
}

print_banner() {
    echo ""
    echo -e "\033[1;36m══════════════════════════════════════════════════════════════════════════\033[0m"
    echo -e "\033[1;33m   🖥️  Raspberry Pi VNC Remote Setup - Secure Remote Access\033[0m"
    echo -e "\033[1;36m══════════════════════════════════════════════════════════════════════════\033[0m"
    echo ""
}

print_access_info() {
    local protocol="http"
    local port_suffix=""

    if [[ "$NGINX_ENABLED" == "true" ]]; then
        protocol="https"
        # nginx uses standard ports, no need to show port in URL
    elif [[ "$DISABLE_SSL" == false ]]; then
        protocol="https"
        port_suffix=":${NOVNC_PORT}"
    else
        port_suffix=":${NOVNC_PORT}"
    fi

    echo ""
    echo -e "\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m"
    echo -e "\033[1;36m║\033[1;33m                    ACCESS INFORMATION                  \033[1;36m║\033[0m"
    echo -e "\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m"
    echo ""

    if [[ "$NGINX_ENABLED" == "true" ]]; then
        echo -e "\033[1;34m  Desktop Access (noVNC):\033[0m"
        echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}/vnc/\033[0m"
        echo ""
        echo -e "\033[1;34m  Terminal Access (ttyd):\033[0m"
        echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}/terminal/\033[0m"
        echo ""
        echo -e "\033[1;32m  nginx reverse proxy is enabled (single port: 443)\033[0m"
    else
        echo -e "\033[1;34m  Desktop Access (noVNC):\033[0m"
        echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}${port_suffix}\033[0m"
        echo ""
        echo -e "\033[1;34m  Terminal Access (ttyd):\033[0m"
        echo -e "     \033[1;36m${protocol}://${DUCK_DOMAIN:-localhost}:${TTYD_PORT}\033[0m"
    fi

    echo ""
    echo -e "\033[1;34m  Username:\033[0m \033[1;33m$TTYD_USERNAME\033[0m"
    # Mask password in console output to avoid exposure in scrollback/logs.
    # Full credentials are written to a root-readable file for reference.
    local masked_pwd="${TTYD_PASSWD:0:3}***"
    echo -e "\033[1;34m  Password:\033[0m \033[1;33m${masked_pwd} (see $PROJECT_DIR/.vnc-credentials)\033[0m"
    # Write full credentials to a protected file (root-only readable)
    if [[ -n "${PROJECT_DIR:-}" ]]; then
        umask 077
        printf 'TTYD Username: %s\nTTYD Password: %s\nVNC Password: %s\n' \
            "$TTYD_USERNAME" "$TTYD_PASSWD" "${VNC_PASSWORD:-}" \
            > "$PROJECT_DIR/.vnc-credentials" 2>/dev/null || true
        chmod 600 "$PROJECT_DIR/.vnc-credentials" 2>/dev/null || true
        umask 022
    fi
    echo ""

    if [[ "$DISABLE_SSL" == true ]] && [[ "$NGINX_ENABLED" != "true" ]]; then
        echo -e "\033[1;33m  WARNING: SSL is disabled. For production, set DUCK_DOMAIN or enable NGINX_ENABLED.\033[0m"
    fi
    echo ""
}
