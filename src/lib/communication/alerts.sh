#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# ALERTS MODULE (Webhook & Email)
# ============================================================================

# Alerts Configuration
export ALERTS_ENABLED="${ALERTS_ENABLED:-false}"
export ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
export ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
export ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-vnc-alerts@localhost}"
export ALERT_SMTP_SERVER="${ALERT_SMTP_SERVER:-localhost:587}"
export ALERT_SMTP_USER="${ALERT_SMTP_USER:-}"
export ALERT_SMTP_PASS="${ALERT_SMTP_PASS:-}"

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
    
    local json_payload=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "level": "$level",
  "message": "$message",
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

# Send email alert
# Arguments:
#   $1 - Alert message
#   $2 - Alert level (info, warning, error)
send_email_alert() {
    [[ "$ALERTS_ENABLED" != "true" ]] && return
    [[ -z "$ALERT_EMAIL_TO" ]] && return
    
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
