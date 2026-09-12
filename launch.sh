#!/bin/bash
# ============================================================================
# VNC Remote Secure - Windows launcher (compatibility wrapper)
# DEPRECATED: Use 'vnc-remote start' instead. This wrapper will be removed
# in a future release.
# Usage: ./launch.sh [--no-ssl]
#   --no-ssl  Start without SSL (HTTP only, for preview/testing)
# ============================================================================
set +e

cd "$(dirname "$0")"
export PROJECT_DIR="$(pwd)"
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Detect Python interpreter (python3 preferred, fall back to python for Windows Git Bash)
PYTHON_BIN="$(command -v python3 || command -v python)"
if [[ -z "$PYTHON_BIN" ]]; then
    echo -e "${RED}  ERROR: python3/python not found on PATH${NC}"
    exit 1
fi

# Parse arguments
USE_SSL=true
if [[ "${1:-}" == "--no-ssl" ]]; then
    USE_SSL=false
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if $USE_SSL; then
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  VNC Remote Secure (Full + SSL)${NC}"
    echo -e "${CYAN}========================================${NC}"
else
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  VNC Remote (NO SSL)${NC}"
    echo -e "${CYAN}========================================${NC}"
fi
echo ""

# ============================================================================
# Load .env file (credentials from config, never hardcoded)
# ============================================================================
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    # Strip carriage returns so CRLF (Windows) .env files work in bash.
    source <(tr -d '\r' < "$PROJECT_DIR/.env")
    set +a
fi

# Read credentials from environment (with secure random fallback)
VNC_PASS="${VNC_PASSWORD:-}"
if [[ -z "$VNC_PASS" ]]; then
    VNC_PASS=$("$PYTHON_BIN" -c "from vnc_remote_secure.core.config import generate_random_password; print(generate_random_password(12))" 2>/dev/null || "$PYTHON_BIN" -c "import secrets, string; chars=string.ascii_letters+string.digits+'!@#\$%^&*'; print(''.join([secrets.choice(string.ascii_letters),secrets.choice(string.digits),secrets.choice('!@#\$%^&*')]+[secrets.choice(chars) for _ in range(9)]))")
    echo -e "${YELLOW}  VNC_PASSWORD not set, generated random${NC}"
fi

TTYD_USER="${TTYD_USERNAME:-admin}"
TTYD_PASS="${TTYD_PASSWD:-}"
if [[ -z "$TTYD_PASS" ]]; then
    TTYD_PASS=$("$PYTHON_BIN" -c "from vnc_remote_secure.core.config import generate_random_password; print(generate_random_password(16))" 2>/dev/null || "$PYTHON_BIN" -c "import secrets, string; chars=string.ascii_letters+string.digits+'!@#\$%^&*'; print(''.join([secrets.choice(string.ascii_letters),secrets.choice(string.digits),secrets.choice('!@#\$%^&*')]+[secrets.choice(chars) for _ in range(13)]))")
    echo -e "${YELLOW}  TTYD_PASSWD not set, generated random${NC}"
fi

# Ports from environment
VNC_PORT="${VNC_PORT:-5900}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
TTYD_PORT="${TTYD_PORT:-5000}"
HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8090}"
LANDING_PORT="${LANDING_PORT:-8000}"
AUDIO_STREAM_PORT="${AUDIO_STREAM_PORT:-7777}"
GAMEPAD_PORT="${GAMEPAD_PORT:-7788}"

# Export for Python components
export VNC_PASSWORD="$VNC_PASS"
export TTYD_USERNAME="$TTYD_USER"
export TTYD_PASSWD="$TTYD_PASS"
export VNC_PORT NOVNC_PORT TTYD_PORT HEALTH_WEB_PORT LANDING_PORT
export AUDIO_STREAM_PORT GAMEPAD_PORT

# Health/landing bind (default 127.0.0.1 for security; set to 0.0.0.0 in .env to expose)
export HEALTH_WEB_HOST="${HEALTH_WEB_HOST:-127.0.0.1}"
export LANDING_HOST="${LANDING_HOST:-127.0.0.1}"
export NOVNC_HOST="${NOVNC_HOST:-${SERVE_NOVNC_HOST:-127.0.0.1}}"
export VNC_HTTP_PORT="${VNC_HTTP_PORT:-5800}"

# ============================================================================
# 0. Free ports
# ============================================================================
echo -e "${YELLOW}Freeing ports...${NC}"
for port in $TTYD_PORT $NOVNC_PORT $HEALTH_WEB_PORT $VNC_PORT $VNC_HTTP_PORT $LANDING_PORT; do
    pids=$(netstat -ano 2>/dev/null | grep ":$port " | grep LISTENING | awk '{print $NF}' | tr -d '\r' | sort -u)
    for pid in $pids; do
        taskkill /PID "$pid" /T /F 2>/dev/null || true
    done
done
taskkill /F /IM winvnc.exe 2>/dev/null || true
sleep 2

# ============================================================================
# 0.5. Update Duck DNS (if configured)
# ============================================================================
if [[ -n "${DUCKDNS_TOKEN:-}" && -n "${DUCK_DOMAIN:-}" ]]; then
    echo -e "${YELLOW}Updating Duck DNS (${DUCK_DOMAIN}.duckdns.org)...${NC}"
    bash "$PROJECT_DIR/scripts/utilities/duckdns_update.sh" || echo -e "${YELLOW}  Duck DNS update failed, continuing...${NC}"
else
    echo -e "${YELLOW}Duck DNS not configured (DUCKDNS_TOKEN/DUCK_DOMAIN not set in .env)${NC}"
fi

# ============================================================================
# 1. Generate SSL self-signed certificate (only if USE_SSL)
# ============================================================================
SSL_CERT=""
SSL_KEY=""
if $USE_SSL; then
    echo ""
    echo -e "${YELLOW}Generating SSL self-signed certificate...${NC}"
    export SSL_DIR="$PROJECT_DIR/data/ssl"
    mkdir -p "$SSL_DIR"
    SSL_CERT="$SSL_DIR/fullchain.pem"
    SSL_KEY="$SSL_DIR/privkey.pem"

    "$PYTHON_BIN" "$PROJECT_DIR/scripts/utilities/generate_certificate.py"

    if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
        echo -e "${GREEN}  SSL certificate generated: $SSL_CERT${NC}"
    else
        echo -e "${RED}  SSL generation failed, continuing without SSL${NC}"
        SSL_CERT=""
        SSL_KEY=""
    fi
else
    echo -e "${YELLOW}  SSL disabled (--no-ssl)${NC}"
fi
export SSL_CERT="$SSL_CERT"
export SSL_KEY="$SSL_KEY"

# ============================================================================
# 2. Start UltraVNC server (Windows desktop)
# ============================================================================
echo ""
echo -e "${YELLOW}Starting UltraVNC server (Windows desktop)...${NC}"
ULTRAVNC_DIR="$PROJECT_DIR/bin/ultravnc/x64"
touch "$ULTRAVNC_DIR/ultravnc.portable"

if [[ ! -f "$ULTRAVNC_DIR/winvnc.exe" ]]; then
    echo -e "${RED}  ERROR: winvnc.exe not found at $ULTRAVNC_DIR${NC}"
    echo -e "${RED}  VNC desktop will not be available${NC}"
else
    VNC_HASH=$(VNC_PASSWORD="$VNC_PASS" "$PYTHON_BIN" "$PROJECT_DIR/scripts/utilities/generate_vnc_password.py" --ultravnc 2>/dev/null | grep "UltraVNC encrypted (hex):" | cut -d: -f2 | tr -d ' ')
    if [[ -z "$VNC_HASH" ]]; then
        echo -e "${RED}  ERROR: VNC hash generation failed. Aborting VNC setup.${NC}"
        exit 1
    fi

    cat > "$ULTRAVNC_DIR/ultravnc.ini" << EOF
[admin]
UseDSM=0
AllowLoopback=1
PortNumber=$VNC_PORT
SocketConnect=1
HTTPConnect=1
HTTPPortNumber=$VNC_HTTP_PORT
AutoPortSelect=0
RemoveWallpaper=0
RemoveAero=0
InputsEnabled=1
LockSettings=0
QueryAccept=0
QuerySetting=2
QueryTimeout=10
QueryIfNoLogon=0
AuthRequired=1
UseRegistry=0
DebugMode=0
Avilog=0
DebugLevel=0
Path=
DisableTrayIcon=0
MSLogonRequired=0
NewMSLogon=0
ConnectPriority=0
AllowShutdown=1
AllowProperties=1
AllowEditClients=1
FileTransferEnabled=1
FTUserImpersonation=1
BlankMonitorEnabled=1
CaptureAlphaBlending=1
BlackAlphaBlending=0
DefaultScale=1
DSMPlugin=
primary=1
secondary=0
IdleTimeout=0
EnableJapInput=0
AuthHosts=
MaxCpu=100
KeepAliveInterval=5
FileTransferTimeout=30
sendbuffer=4096

[ultravnc]
passwd=$VNC_HASH
passwd2=

[poll]
TurboMode=1
PollUnderCursor=0
PollForeground=0
PollFullScreen=1
OnlyPollConsole=0
OnlyPollOnEvent=1
EnableDriver=0
EnableHook=1
EnableVirtual=0
SingleWindow=0
SingleWindowName=
EOF

    USER_VNC_DIR="$LOCALAPPDATA/UltraVNC"
    mkdir -p "$USER_VNC_DIR" 2>/dev/null
    cp "$ULTRAVNC_DIR/ultravnc.ini" "$USER_VNC_DIR/ultravnc.ini" 2>/dev/null

    "$ULTRAVNC_DIR/winvnc.exe" &
    sleep 3

    if netstat -ano 2>/dev/null | grep ":$VNC_PORT " | grep -q LISTENING; then
        echo -e "${GREEN}  UltraVNC running on port $VNC_PORT${NC}"
    else
        echo -e "${RED}  UltraVNC failed to start${NC}"
    fi
fi

# ============================================================================
# 3. Start web terminal (Python tornado-based, replaces ttyd)
# ============================================================================
echo ""
echo -e "${YELLOW}Starting web terminal on port $TTYD_PORT...${NC}"
"$PYTHON_BIN" -m vnc_remote_secure.services.terminal &
TTYD_PID=$!
sleep 2
if netstat -ano 2>/dev/null | grep ":$TTYD_PORT " | grep -q LISTENING; then
    echo -e "${GREEN}  Web terminal running on port $TTYD_PORT (PID: $TTYD_PID)${NC}"
else
    echo -e "${RED}  Web terminal failed to start${NC}"
fi

# ============================================================================
# 4. Start websockify (noVNC proxy to VNC server)
# ============================================================================
echo ""
echo -e "${YELLOW}Starting websockify (noVNC) on port $NOVNC_PORT...${NC}"
NOVNC_DIR="$PROJECT_DIR/novnc"
if [[ ! -d "$NOVNC_DIR" ]]; then
    echo "  Downloading noVNC..."
    git clone --depth 1 https://github.com/novnc/noVNC.git "$NOVNC_DIR" 2>/dev/null
fi

if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
    CERT_WIN=$(cygpath -w "$SSL_CERT" 2>/dev/null || echo "$SSL_CERT")
    KEY_WIN=$(cygpath -w "$SSL_KEY" 2>/dev/null || echo "$SSL_KEY")
    "$PYTHON_BIN" -m websockify --web "$NOVNC_DIR" \
        --cert "$CERT_WIN" --key "$KEY_WIN" --ssl-only \
        "$NOVNC_HOST:$NOVNC_PORT" localhost:$VNC_PORT &
else
    "$PYTHON_BIN" -m websockify --web "$NOVNC_DIR" \
        "$NOVNC_HOST:$NOVNC_PORT" localhost:$VNC_PORT &
fi
WS_PID=$!
sleep 3
if netstat -ano 2>/dev/null | grep ":$NOVNC_PORT " | grep -q LISTENING; then
    echo -e "${GREEN}  websockify running on port $NOVNC_PORT → localhost:$VNC_PORT (PID: $WS_PID)${NC}"
else
    echo -e "${RED}  websockify failed to start${NC}"
fi

# ============================================================================
# 5. Start health web server
# ============================================================================
echo ""
echo -e "${YELLOW}Starting health web server on port $HEALTH_WEB_PORT...${NC}"
export HEALTH_WEB_ENABLED=true
export DUCK_DOMAIN=""
export DISABLE_SSL=$($USE_SSL && echo false || echo true)
export HEALTHCHECK_ENABLED=true
export MONITORING_ENABLED=false
export NGINX_ENABLED=false
export FAIL2BAN_ENABLED=false
export RECORDING_ENABLED=false
export USER_UI_ENABLED=false
export TEMP_USER="$USERNAME"
export LOG_LEVEL=INFO
export VERBOSE=false
export KEEP_TEMP_USER="${KEEP_TEMP_USER:-false}"

"$PYTHON_BIN" -m vnc_remote_secure.services.health &
HEALTH_PID=$!
sleep 2
if netstat -ano 2>/dev/null | grep ":$HEALTH_WEB_PORT " | grep -q LISTENING; then
    echo -e "${GREEN}  Health web server running on $HEALTH_WEB_PORT (PID: $HEALTH_PID)${NC}"
else
    echo -e "${RED}  Health web server failed to start${NC}"
fi

# ============================================================================
# 6. Start landing page (portal to all services)
# ============================================================================
echo ""
echo -e "${YELLOW}Starting landing page on port $LANDING_PORT...${NC}"
"$PYTHON_BIN" -m vnc_remote_secure.services.landing &
LANDING_PID=$!
sleep 2
if netstat -ano 2>/dev/null | grep ":$LANDING_PORT " | grep -q LISTENING; then
    echo -e "${GREEN}  Landing page running on $LANDING_PORT (PID: $LANDING_PID)${NC}"
else
    echo -e "${RED}  Landing page failed to start${NC}"
fi

# ============================================================================
# 6.5. Start audio stream server (if enabled)
# ============================================================================
if [[ "${AUDIO_STREAM_ENABLED:-false}" == "true" ]]; then
    echo ""
    echo -e "${YELLOW}Starting audio stream server on port $AUDIO_STREAM_PORT...${NC}"
    "$PYTHON_BIN" -m vnc_remote_secure.services.audio &
    AUDIO_PID=$!
    sleep 2
    if netstat -ano 2>/dev/null | grep ":$AUDIO_STREAM_PORT " | grep -q LISTENING; then
        echo -e "${GREEN}  Audio stream running on $AUDIO_STREAM_PORT (PID: $AUDIO_PID)${NC}"
    else
        echo -e "${RED}  Audio stream failed to start (is ffmpeg installed?)${NC}"
    fi
else
    echo -e "${YELLOW}  Audio streaming disabled (set AUDIO_STREAM_ENABLED=true in .env)${NC}"
    AUDIO_PID=""
fi

# ============================================================================
# 6.6. Start gamepad forwarding server (if enabled)
# ============================================================================
if [[ "${GAMEPAD_ENABLED:-false}" == "true" ]]; then
    echo ""
    echo -e "${YELLOW}Starting gamepad forwarding server on port $GAMEPAD_PORT...${NC}"
    "$PYTHON_BIN" -m vnc_remote_secure.services.gamepad &
    GAMEPAD_PID=$!
    sleep 2
    if netstat -ano 2>/dev/null | grep ":$GAMEPAD_PORT " | grep -q LISTENING; then
        echo -e "${GREEN}  Gamepad forwarding running on $GAMEPAD_PORT (PID: $GAMEPAD_PID)${NC}"
    else
        echo -e "${RED}  Gamepad forwarding failed to start${NC}"
    fi
else
    echo -e "${YELLOW}  Gamepad forwarding disabled (set GAMEPAD_ENABLED=true in .env)${NC}"
    GAMEPAD_PID=""
fi

# ============================================================================
# 7. Show access URLs
# ============================================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Access URLs${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

ALL_IPS=$(ipconfig 2>/dev/null | grep -i "IPv4" | sed 's/.*: //' | tr -d '\r' | grep -v "169.254" | sort -u)

PROTOCOL=$($USE_SSL && echo https || echo http)

echo "Local access (this machine):"
echo "  Portal (landing page): $PROTOCOL://localhost:$LANDING_PORT"
echo "  VNC desktop (noVNC):   $PROTOCOL://localhost:$NOVNC_PORT/vnc.html"
echo "  Terminal (web):        $PROTOCOL://localhost:$TTYD_PORT"
echo "  Health (JSON):         $PROTOCOL://localhost:$HEALTH_WEB_PORT/health"
echo "  Health (full):         $PROTOCOL://localhost:$HEALTH_WEB_PORT/health/all"
echo "  UltraVNC HTTP:         http://localhost:$VNC_HTTP_PORT"
if [[ "${AUDIO_STREAM_ENABLED:-false}" == "true" ]]; then
    echo "  Audio receiver:        $PROTOCOL://localhost:$LANDING_PORT/audio_receiver.html"
fi
if [[ "${GAMEPAD_ENABLED:-false}" == "true" ]]; then
    echo "  Gamepad forwarding:    $PROTOCOL://localhost:$LANDING_PORT/gamepad.html"
fi
echo ""

echo "Remote access (from other devices on the same network):"
for ip in $ALL_IPS; do
    echo "  --- IP: $ip ---"
    echo "    Portal:        $PROTOCOL://$ip:$LANDING_PORT"
    echo "    VNC desktop:   $PROTOCOL://$ip:$NOVNC_PORT/vnc.html"
    echo "    Terminal:      $PROTOCOL://$ip:$TTYD_PORT"
    echo "    Health (JSON):  $PROTOCOL://$ip:$HEALTH_WEB_PORT/health"
    echo "    Health (full):  $PROTOCOL://$ip:$HEALTH_WEB_PORT/health/all"
    echo ""
done

echo -e "${YELLOW}Credentials:${NC}"
echo "  Terminal (web):    user=$TTYD_USER  pass=*** (check .env or above if generated)"
echo "  VNC desktop:       pass=*** (check .env or above if generated, 8 char limit)"
echo ""

if $USE_SSL; then
    echo -e "${YELLOW}Note: SSL is self-signed. Browser will show security warning.${NC}"
    echo -e "${YELLOW}      Click 'Advanced' → 'Proceed' to accept.${NC}"
    echo ""
fi

echo -e "${YELLOW}Windows Firewall: run this as Admin to allow remote access:${NC}"
echo "  New-NetFirewallRule -DisplayName \"VNC Remote\" -Direction Inbound -LocalPort $TTYD_PORT,$NOVNC_PORT,$HEALTH_WEB_PORT,$VNC_PORT,$LANDING_PORT -Protocol TCP -Action Allow"
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Services running. Press Ctrl+C to stop.${NC}"
echo -e "${CYAN}========================================${NC}"

# Save PIDs for cleanup
echo "$TTYD_PID" > /tmp/vnc_remote_ttyd.pid
echo "$WS_PID" > /tmp/vnc_remote_ws.pid
echo "$LANDING_PID" > /tmp/vnc_remote_landing.pid
echo "$HEALTH_PID" > /tmp/vnc_remote_health.pid
[[ -n "$AUDIO_PID" ]] && echo "$AUDIO_PID" > /tmp/vnc_remote_audio.pid
[[ -n "$GAMEPAD_PID" ]] && echo "$GAMEPAD_PID" > /tmp/vnc_remote_gamepad.pid

cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all services...${NC}"
    taskkill /F /IM winvnc.exe 2>/dev/null || true
    for pid_file in /tmp/vnc_remote_ttyd.pid /tmp/vnc_remote_ws.pid /tmp/vnc_remote_health.pid /tmp/vnc_remote_landing.pid /tmp/vnc_remote_audio.pid /tmp/vnc_remote_gamepad.pid; do
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" | tr -d '\r')
            taskkill /PID "$pid" /T /F 2>/dev/null || kill "$pid" 2>/dev/null || true
            rm -f "$pid_file"
        fi
    done
    echo -e "${GREEN}All services stopped.${NC}"
}

trap cleanup EXIT INT TERM
wait
