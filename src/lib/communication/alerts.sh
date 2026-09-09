#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# ALERTS MODULE (Webhook & Email)
# ============================================================================
# Configuration is centralized in core/config.sh (single source of truth).

# json_escape() is defined in notifications.sh (loaded before this module).

# Send webhook alert
# Arguments:
#   $1 - Alert message
#   $2 - Alert level (info, warning, error)
send_webhook_alert() {
    [[ "$ALERTS_ENABLED" != "true" ]] && return
    [[ -z "$ALERT_WEBHOOK_URL" ]] && return

    local message="$1"
    local level="${2:-info}"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local esc_message esc_level
    esc_message=$(json_escape "$message")
    esc_level=$(json_escape "$level")

    local json_payload=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "level": "$esc_level",
  "message": "$esc_message",
  "service": "vnc-remote"
}
EOF
)

    if curl -s -X POST "$ALERT_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$json_payload" > /dev/null 2>&1; then
        success "Webhook alert sent"
    else
        warn "Failed to send webhook alert"
    fi
}

# Validate an email address format (prevents header injection)
# Arguments:
#   $1 - Email address to validate
# Returns:
#   0 if valid, 1 if invalid
validate_email() {
    local email="$1"
    [[ -z "$email" ]] && return 1
    # Reject newlines, spaces, and other header injection characters
    [[ "$email" =~ [\ \n\r\t] ]] && return 1
    # Basic email format validation
    [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

# Send email alert
# Arguments:
#   $1 - Alert message
#   $2 - Alert level (info, warning, error)
send_email_alert() {
    [[ "$ALERTS_ENABLED" != "true" ]] && return
    [[ -z "$ALERT_EMAIL_TO" ]] && return

    # Validate email addresses to prevent header injection
    if ! validate_email "$ALERT_EMAIL_TO"; then
        warn "ALERT_EMAIL_TO is not a valid email address, skipping email alert"
        return
    fi
    if ! validate_email "$ALERT_EMAIL_FROM"; then
        warn "ALERT_EMAIL_FROM is not a valid email address, skipping email alert"
        return
    fi

    local message="$1"
    local level="${2:-info}"
    local subject="[VNC Remote] $level: $message"

    if command -v mail &>/dev/null; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL_TO"
        success "Email alert sent"
    elif command -v sendmail &>/dev/null; then
        echo "Subject: $subject
To: $ALERT_EMAIL_TO
From: $ALERT_EMAIL_FROM

$message" | sendmail -t
        success "Email alert sent"
    else
        warn "mail/sendmail not available for email alerts"
    fi
}

# Send alert (webhook and/or email)
# Arguments:
#   $1 - Alert message
#   $2 - Alert level (info, warning, error)
send_alert() {
    local message="$1"
    local level="${2:-info}"

    send_webhook_alert "$message" "$level"
    send_email_alert "$message" "$level"
}

# Alert on service start
alert_service_start() {
    local service="$1"
    local message="Service started: $service"
    send_alert "$message" "info"
}

# Alert on service failure
alert_service_failure() {
    local service="$1"
    local message="Service failed: $service"
    send_alert "$message" "error"
}

# Alert on SSL expiry warning
alert_ssl_expiry() {
    local days_left="$1"
    local message="SSL certificate expires in $days_left days"
    send_alert "$message" "warning"
}

# Alert on SSL renewal
alert_ssl_renewal() {
    local message="SSL certificate renewed successfully"
    send_alert "$message" "info"
}

# Alert on unauthorized access attempt
alert_unauthorized_access() {
    local ip="$1"
    local service="$2"
    local message="Unauthorized access attempt to $service from $ip"
    send_alert "$message" "warning"
}

# Alert on system error
alert_system_error() {
    local error="$1"
    local message="System error: $error"
    send_alert "$message" "error"
}

# Alert on cleanup
alert_cleanup() {
    local message="Cleanup completed successfully"
    send_alert "$message" "info"
}

# Alert on startup
alert_startup() {
    local message="VNC Remote services started successfully"
    local access_info="noVNC: http://localhost:$NOVNC_PORT | ttyd: http://localhost:$TTYD_PORT"
    send_alert "$access_info" "info"
}

# Alert on shutdown
alert_shutdown() {
    local message="VNC Remote services stopped"
    send_alert "$message" "info"
}
