#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2155,SC2086
set -e
set -o pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$SCRIPT_DIR/lib"

# Source all modules
source "$LIB_DIR/core/config.sh"
source "$LIB_DIR/core/utils.sh"
source "$LIB_DIR/security/ssl.sh"
source "$LIB_DIR/web/nginx.sh"
source "$LIB_DIR/security/user.sh"
source "$LIB_DIR/core/services.sh"
source "$LIB_DIR/communication/notifications.sh"
source "$LIB_DIR/security/fail2ban.sh"
source "$LIB_DIR/monitoring/healthcheck.sh"
source "$LIB_DIR/monitoring/health_web_server.sh"
source "$LIB_DIR/security/portknock.sh"
source "$LIB_DIR/monitoring/monitoring.sh"
source "$LIB_DIR/features/recording.sh"
source "$LIB_DIR/web/user_ui.sh"
source "$LIB_DIR/communication/alerts.sh"

# Handle command line arguments
handle_command "$1"

# ============================================================================
# ERROR HANDLING
# ============================================================================

cleanup() {
    local exit_code=$?
    log "yellow" "Cleaning up..."
    
    # Stop services if they were started
    if [[ "$exit_code" -ne 0 ]]; then
        log "red" "Script failed with exit code: $exit_code"
        # Attempt to stop services that might have been started
        pkill -f "tigervncserver" 2>/dev/null || true
        pkill -f "novnc_proxy" 2>/dev/null || true
        pkill -f "ttyd" 2>/dev/null || true
    fi
    
    # Stop health web server
    stop_health_web_server
    
    # Remove temporary user if KEEP_TEMP_USER is false
    if [[ "$KEEP_TEMP_USER" == "false" ]] && id "$TEMP_USER" &>/dev/null; then
        log "yellow" "Removing temporary user: $TEMP_USER"
        
        # Kill all processes belonging to the user first
        sudo pkill -u "$TEMP_USER" 2>/dev/null || true
        sleep 2
        sudo pkill -9 -u "$TEMP_USER" 2>/dev/null || true
        
        # Kill specific processes that might hold the user
        sudo pkill -f "ssh-agent.*$TEMP_USER" 2>/dev/null || true
        sudo pkill -f "/usr/bin/ssh-agent" 2>/dev/null || true
        
        sleep 1
        
        # Try to remove the user
        if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
            log "green" "Successfully removed temporary user $TEMP_USER"
        else
            # Force approach if needed
            local user_processes=$(ps -u "$TEMP_USER" -o pid= 2>/dev/null | tr -d ' ')
            if [[ -n "$user_processes" ]]; then
                for pid in $user_processes; do
                    sudo kill -9 "$pid" 2>/dev/null || true
                done
                sleep 1
            fi
            
            if sudo userdel -r "$TEMP_USER" 2>/dev/null; then
                log "green" "Successfully removed temporary user $TEMP_USER (force)"
            else
                log "red" "Failed to remove temporary user $TEMP_USER"
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

    # Setup Port Knocking if enabled
    if [[ "$PORT_KNOCK_ENABLED" == "true" ]]; then
        print_section "Port Knocking Configuration"
        install_knockd
        configure_knockd
        setup_port_knocking_firewall
        start_knockd
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
    
    # Start health web server
    start_health_web_server &

    wait
}

main
