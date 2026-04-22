#!/bin/bash
# shellcheck disable=SC1091,SC2034,SC2155,SC2086
set -e
set -o pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$SCRIPT_DIR/lib"

# Source all modules
source "$LIB_DIR/config.sh"
source "$LIB_DIR/utils.sh"
source "$LIB_DIR/ssl.sh"
source "$LIB_DIR/user.sh"
source "$LIB_DIR/services.sh"
source "$LIB_DIR/notifications.sh"
source "$LIB_DIR/fail2ban.sh"
source "$LIB_DIR/healthcheck.sh"
source "$LIB_DIR/portknock.sh"
source "$LIB_DIR/monitoring.sh"
source "$LIB_DIR/recording.sh"
source "$LIB_DIR/user_ui.sh"
source "$LIB_DIR/alerts.sh"

# Handle command line arguments
handle_command "$1"

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_banner

    print_section "Configuration Validation"
    if ! validate_config; then
        die "Configuration validation failed. Please fix the errors above."
    fi

    # Setup trap for cleanup after validation
    trap cleanup INT EXIT

    print_section "Dependency Installation"
    install_dependencies

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
        log "cyan" "🔐 Fixing SSL permissions for $TEMP_USER..."
        fix_ssl_permissions
    fi

    print_section "Service Startup"
    inject_beef
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

    print_section "Access Information"
    print_access_info
    notify_startup
    alert_startup
    echo ""
    success "Setup complete. Press CTRL+C to stop services."
    echo ""

    wait
}

main
