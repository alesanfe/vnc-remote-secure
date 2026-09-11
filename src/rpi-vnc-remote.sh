#!/bin/bash
# shellcheck disable=SC1091
set -e
set -o pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
export PROJECT_DIR
LIB_DIR="$SCRIPT_DIR/lib"

# Load .env file if it exists (from project root or current directory)
for _env_file in "$PROJECT_DIR/.env" "$PWD/.env"; do
    if [[ -f "$_env_file" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "$_env_file"
        set +a
        break
    fi
done
unset _env_file

# Source platform detection FIRST (sets OS_TYPE, provides helpers)
source "$LIB_DIR/platform/detect.sh"

# Source all modules
source "$LIB_DIR/core/config.sh"
source "$LIB_DIR/core/logging.sh"
source "$LIB_DIR/core/validation.sh"
source "$LIB_DIR/core/error_handling.sh"
source "$LIB_DIR/core/utils.sh"
source "$LIB_DIR/core/process_utils.sh"
source "$LIB_DIR/security/ssl.sh"
source "$LIB_DIR/web/nginx.sh"
source "$LIB_DIR/security/user.sh"
source "$LIB_DIR/core/services.sh"
source "$LIB_DIR/communication/notifications.sh"
source "$LIB_DIR/security/fail2ban.sh"
source "$LIB_DIR/monitoring/healthcheck.sh"
source "$LIB_DIR/monitoring/health_web_server.sh"
source "$LIB_DIR/monitoring/monitoring.sh"
source "$LIB_DIR/features/recording.sh"
source "$LIB_DIR/web/user_ui.sh"
source "$LIB_DIR/communication/alerts.sh"

# Source platform-specific backend LAST, so it can override
# Linux-specific functions with Windows/macOS implementations.
load_platform_backend

# On Windows, warn if not running as Administrator
if is_windows; then
    _platform_warn_if_not_admin
fi

# ============================================================================
# ERROR HANDLING
# ============================================================================

# Cleanup function for trap: runs on EXIT, INT, TERM, ERR.
# Stops the health monitor/web server and removes the temp user (unless
# KEEP_TEMP_USER=true). The 'stop' command calls stop_services() first,
# then exits 0 which triggers this trap.
_CLEANING_UP=0
HEALTH_MONITOR_PID=""

cleanup() {
    # Guard against double execution (ERR then EXIT)
    (( _CLEANING_UP )) && return
    _CLEANING_UP=1

    local exit_code=$?
    log "yellow" "Cleaning up..."

    # Stop services if they were started
    if [[ "$exit_code" -ne 0 ]]; then
        log "red" "Script failed with exit code: $exit_code"
        if is_windows; then
            kill_processes_by_pattern "tvnserver" 5 || true
            kill_processes_by_pattern "websockify" 5 || true
        else
            kill_processes_by_pattern "tigervncserver" 5 || true
        fi
        kill_processes_by_pattern "novnc_proxy" 5 || true
        kill_processes_by_pattern "ttyd" 5 || true
    fi

    # Stop health monitor (infinite loop in background)
    if [[ -n "$HEALTH_MONITOR_PID" ]] && kill -0 "$HEALTH_MONITOR_PID" 2>/dev/null; then
        log "yellow" "Stopping health monitor (PID: $HEALTH_MONITOR_PID)..."
        kill "$HEALTH_MONITOR_PID" 2>/dev/null || true
    fi

    # Stop health web server
    stop_health_web_server

    # Remove temporary user if KEEP_TEMP_USER is false
    # On Windows, remove_temp_user is a no-op (no temp user created)
    if [[ "$KEEP_TEMP_USER" == "false" ]] && id "$TEMP_USER" &>/dev/null; then
        if is_windows; then
            # Windows: no temp user to remove, just clean up processes
            log "yellow" "Cleaning up processes for: $TEMP_USER"
            kill_user_processes_gracefully "$TEMP_USER" 10 || true
        else
            log "yellow" "Removing temporary user: $TEMP_USER"
            kill_user_processes_gracefully "$TEMP_USER" 10 || true
            kill_processes_by_pattern "ssh-agent.*$TEMP_USER" 5 || true
            kill_processes_by_pattern "/usr/bin/ssh-agent" 5 || true
            sleep 1
            if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
                log "green" "Successfully removed temporary user $TEMP_USER"
            else
                if ! kill_user_processes_gracefully "$TEMP_USER" 5; then
                    log "yellow" "Some processes still running, attempting final cleanup..."
                    kill_user_processes_gracefully "$TEMP_USER" 2 || true
                fi
                if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
                    log "green" "Successfully removed temporary user $TEMP_USER (force)"
                else
                    log "red" "Failed to remove temporary user $TEMP_USER"
                fi
            fi
        fi
    fi
}

# Setup trap for cleanup on exit, interrupt, and error
trap cleanup EXIT INT TERM ERR

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_banner

    # Initialize file logging
    init_logging

    print_section "Configuration Validation"
    if ! validate_config; then
        die "Configuration validation failed. Please fix the errors above."
    fi

    print_section "Dependency Installation"
    install_dependencies

    # Setup nginx if enabled
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        print_section "Nginx Reverse Proxy Setup"
        install_nginx
        configure_nginx
    fi

    # Setup Fail2ban if enabled
    if [[ "$FAIL2BAN_ENABLED" == "true" ]]; then
        print_section "Fail2ban Configuration"
        install_fail2ban
        configure_fail2ban
        start_fail2ban
    fi


    # Setup Monitoring if enabled
    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        print_section "Monitoring Stack Setup"
        install_node_exporter
        install_prometheus
        install_grafana
        configure_prometheus
        configure_grafana
        start_node_exporter
        start_prometheus
        start_grafana
    fi

    # Setup Session Recording if enabled
    if [[ "$RECORDING_ENABLED" == "true" ]]; then
        print_section "Session Recording Setup"
        install_asciinema
        create_recording_dir
        start_ttyd_recording
    fi

    # Setup User Management UI if enabled
    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        print_section "User Management UI Setup"
        install_flask_deps
        create_user_ui
        start_user_ui
    fi

    # Update Duck DNS if configured (before SSL so certbot can use the domain)
    if [[ -n "$DUCKDNS_TOKEN" && -n "$DUCK_DOMAIN" ]]; then
        print_section "Duck DNS Update"
        log "cyan" "Updating $DUCK_DOMAIN.duckdns.org..."
        if bash "$PROJECT_DIR/scripts/duckdns_update.sh"; then
            log "green" "Duck DNS updated successfully"
        else
            log "yellow" "Duck DNS update failed, continuing..."
        fi
    fi

    print_section "SSL Configuration"
    setup_ssl

    print_section "User Setup"
    create_temp_user

    # Fix SSL permissions now that user exists
    if [[ "$DISABLE_SSL" == "false" ]]; then
        log "cyan" "Fixing SSL permissions for $TEMP_USER..."
        fix_ssl_permissions
    fi

    print_section "Service Startup"
    start_vnc_server
    notify_service_start "VNC Server"
    alert_service_start "VNC Server"
    print_separator
    start_ttyd
    notify_service_start "ttyd"
    alert_service_start "ttyd"
    print_separator
    start_novnc
    notify_service_start "noVNC"
    alert_service_start "noVNC"

    # Start nginx if enabled
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        print_separator
        start_nginx
        notify_service_start "nginx"
        alert_service_start "nginx"
    fi

    print_section "Access Information"
    print_access_info
    notify_startup
    alert_startup
    echo ""
    success "Setup complete. Starting continuous health monitoring..."
    echo ""

    # Start continuous health monitoring
    start_health_monitor &
    HEALTH_MONITOR_PID=$!

    # Start health web server
    start_health_web_server &

    wait
}

# ============================================================================
# ENTRY POINT
# ============================================================================
# Dispatch to the appropriate function based on the first argument.
# If no command is given, default to 'setup' (full install + start).
handle_command "${1:-setup}"
