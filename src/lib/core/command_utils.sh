#!/bin/bash
# shellcheck disable=SC2034
# ============================================================================
# COMMAND HANDLING UTILITIES
# ============================================================================

show_help() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
  setup    Install dependencies and configure the system (default)
  start    Start all services
  stop     Stop all services and cleanup
  restart  Restart all services
  status   Check system status
  help     Show this help message

Environment Variables (set in .env or export before running):
  TTYD_USERNAME       Username for ttyd authentication (default: current user)
  TTYD_PASSWD         Password for ttyd (auto-generated if not set)
  TEMP_USER           Temporary user name (default: remote)
  TEMP_USER_PASS      Temporary user password (default: TTYD_PASSWD)
  EMAIL               Email for SSL certificate (required for SSL)
  NOVNC_PORT          Port for noVNC (default: 6080)
  TTYD_PORT           Port for ttyd (default: 5000)
  VNC_PORT            Port for VNC (default: 5901)
  VNC_PASSWORD        Password for VNC (auto-generated if not set)
  SSL_DIR             Directory for SSL certificates (default: data/ssl)
  DUCK_DOMAIN         Domain for SSL certificate (required for SSL)
  SSL_RENEW_DAYS      Days before SSL expiration to renew (default: 30)
  NGINX_ENABLED       Enable nginx reverse proxy (default: false)
  NGINX_HTTP_PORT     nginx HTTP port (default: 80)
  NGINX_HTTPS_PORT    nginx HTTPS port (default: 443)
  FAIL2BAN_ENABLED    Enable Fail2ban protection (default: false)
  MONITORING_ENABLED  Enable monitoring stack (default: false)
  RECORDING_ENABLED   Enable session recording (default: false)
  USER_UI_ENABLED     Enable user management UI (default: false)
  USER_UI_PASSWORD    Password for user UI (auto-generated if not set)
  HEALTH_WEB_ENABLED  Enable health web server (default: true)
  HEALTH_WEB_PORT     Health web server port (default: 8080)
  LOG_LEVEL           Logging level (DEBUG, INFO, WARN, ERROR) (default: INFO)
  VERBOSE             Enable verbose output (default: false)
  KEEP_TEMP_USER      Keep temp user on exit (default: false)

Examples:
  TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org $0 setup
  $0 start
  $0 stop
  $0 status

EOF
}

handle_command() {
    local command="$1"

    case "$command" in
        "setup")
            log_info "Starting system setup" "COMMAND"
            main
            ;;
        "start")
            log_info "Starting services" "COMMAND"
            start_services
            # Keep the script alive: wait for background jobs (health monitor, web server)
            # Otherwise the EXIT trap would kill everything immediately.
            wait
            ;;
        "stop")
            log_info "Stopping services" "COMMAND"
            stop_services
            # EXIT trap will handle temp user removal and health web server shutdown.
            exit 0
            ;;
        "restart")
            log_info "Restarting services" "COMMAND"
            stop_services
            sleep 2
            start_services
            # Keep the script alive for the newly started background jobs.
            wait
            ;;
        "status")
            log_info "Checking system status" "COMMAND"
            check_system_status
            ;;
        "help"|"--help"|"-h")
            show_help
            exit 0
            ;;
        "")
            log_error "No command specified" "COMMAND"
            show_help
            exit 1
            ;;
        *)
            log_error "Unknown command: $command" "COMMAND"
            show_help
            exit 1
            ;;
    esac
}

# Service management commands
start_services() {
    log_info "Starting all services" "SERVICES"

    # Initialize error handling
    init_error_handling
    init_logging

    # Start core services
    start_vnc_server
    start_ttyd
    start_novnc

    # Start optional services if enabled
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        start_nginx
    fi

    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        start_node_exporter
        start_prometheus
        start_grafana
    fi

    if [[ "$RECORDING_ENABLED" == "true" ]]; then
        start_ttyd_recording
    fi

    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        start_user_ui
    fi

    # Start health monitoring
    start_health_monitor &
    start_health_web_server &

    log_success "All services started successfully" "SERVICES"
    print_access_info
}

stop_services() {
    log_info "Stopping all services" "SERVICES"

    # Stop optional services first
    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        stop_user_ui
    fi

    if [[ "$RECORDING_ENABLED" == "true" ]]; then
        pkill -f "ttyd.*recording" 2>/dev/null || true
    fi

    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        stop_monitoring
    fi

    if [[ "$NGINX_ENABLED" == "true" ]]; then
        stop_nginx
    fi

    # Stop core services
    kill_process_on_port "$NOVNC_PORT"
    kill_process_on_port "$TTYD_PORT"
    kill_vnc_server

    # Stop health monitoring
    pkill -f "health_monitor" 2>/dev/null || true
    stop_health_web_server

    log_success "All services stopped successfully" "SERVICES"
}

restart_services() {
    log_info "Restarting all services" "SERVICES"

    stop_services
    sleep 3
    start_services

    log_success "All services restarted successfully" "SERVICES"
}

check_system_status() {
    log_info "Checking system status" "STATUS"

    # Check core services
    check_service_status "VNC Server" "tigervncserver"
    check_service_status "ttyd" "ttyd"
    check_service_status "noVNC" "novnc"

    # Check optional services
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        check_service_status "nginx" "nginx"
    fi

    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        check_service_status "Prometheus" "prometheus"
        check_service_status "Grafana" "grafana"
        check_service_status "Node Exporter" "node_exporter"
    fi

    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        check_service_status "User UI" "user_ui"
    fi

    # Check system resources
    log_system_resources

    # Check SSL certificates
    if [[ "$DISABLE_SSL" == "false" ]]; then
        check_ssl_status
    fi

    log_success "System status check completed" "STATUS"
}

check_service_status() {
    local service_name="$1"
    local process_pattern="$2"

    if pgrep -f "$process_pattern" > /dev/null; then
        log_success "$service_name is running" "STATUS"
        return 0
    else
        log_error "$service_name is not running" "STATUS"
        return 1
    fi
}

check_ssl_status() {
    if [[ -f "$SSL_CERT" ]]; then
        local expiry_date
        expiry_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)

        if openssl x509 -checkend 86400 -noout -in "$SSL_CERT" 2>/dev/null; then
            log_success "SSL certificate is valid (expires: $expiry_date)" "STATUS"
            return 0
        else
            log_warn "SSL certificate expires soon or is expired (expires: $expiry_date)" "STATUS"
            return 1
        fi
    else
        log_error "SSL certificate not found" "STATUS"
        return 1
    fi
}
