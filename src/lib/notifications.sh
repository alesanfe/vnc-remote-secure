#!/bin/bash
# ============================================================================
# NOTIFICATIONS MODULE
# ============================================================================

# Discord Configuration
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
export DISCORD_ENABLED="${DISCORD_ENABLED:-false}"

# Send Discord notification
# Arguments:
#   $1 - Message content
#   $2 - Optional: username (default: "VNC Remote")
#   $3 - Optional: color (decimal for embed)
# Globals:
#   DISCORD_WEBHOOK_URL, DISCORD_ENABLED
send_discord_notification() {
    [[ "$DISCORD_ENABLED" != "true" ]] && return
    [[ -z "$DISCORD_WEBHOOK_URL" ]] && {
        warn "Discord enabled but webhook URL not set"
        return
    }
    
    local message="$1"
    local username="${2:-VNC Remote}"
    local color="${3:-3447003}"  # Blue by default
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local json_payload=$(cat <<EOF
{
  "username": "$username",
  "embeds": [
    {
      "description": "$message",
      "color": $color,
      "timestamp": "$timestamp"
    }
  ]
}
EOF
)
    
    if curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$json_payload" > /dev/null 2>&1; then
        success "Discord notification sent"
    else
        warn "Failed to send Discord notification"
    fi
}

# Discord notification with color codes
# Arguments:
#   $1 - Message
#   $2 - Color: success (green), warning (yellow), error (red), info (blue)
send_discord_alert() {
    local message="$1"
    local level="$2"
    local color
    
    case "$level" in
        success|green) color=3066993 ;;
        warning|yellow) color=15105570 ;;
        error|red) color=15158332 ;;
        info|blue) color=3447003 ;;
        *) color=3447003 ;;
    esac
    
    send_discord_notification "$message" "VNC Remote" "$color"
}

# Notify service startup
notify_service_start() {
    local service="$1"
    local message="Service started: $service"
    info "$message"
    send_discord_alert "$message" "success"
}

# Notify service failure
notify_service_failure() {
    local service="$1"
    local message="Service failed: $service"
    warn "$message"
    send_discord_alert "$message" "error"
}

# Notify SSL certificate expiry warning
notify_ssl_expiry() {
    local days_left="$1"
    local message="SSL certificate expires in $days_left days"
    warn "$message"
    send_discord_alert "$message" "warning"
}

# Notify successful SSL renewal
notify_ssl_renewal() {
    local message="SSL certificate renewed successfully"
    success "$message"
    send_discord_alert "$message" "success"
}

# Notify access attempt
notify_access_attempt() {
    local ip="$1"
    local service="$2"
    local message="Access attempt to $service from $ip"
    info "$message"
    send_discord_alert "$message" "info"
}

# Notify cleanup complete
notify_cleanup_complete() {
    local message="Cleanup completed successfully"
    success "$message"
    send_discord_alert "$message" "success"
}

# Notify system error
notify_system_error() {
    local error="$1"
    local message="System error: $error"
    die "$message"
    send_discord_alert "$message" "error"
}

# Send startup notification
notify_startup() {
    local message="VNC Remote services started successfully"
    local access_info="noVNC: http://localhost:$NOVNC_PORT | ttyd: http://localhost:$TTYD_PORT"
    success "$message"
    send_discord_notification "$access_info" "VNC Remote" 3066993
}

# Send shutdown notification
notify_shutdown() {
    local message="VNC Remote services stopped"
    info "$message"
    send_discord_notification "$message" "VNC Remote" 15105570
}
