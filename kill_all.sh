#!/bin/bash
# DEPRECATED: Use 'vnc-remote stop --force' instead.
# This script will be removed in a future release.
echo "[DEPRECATED] kill_all.sh is deprecated. Use: vnc-remote stop --force" >&2
# Kill all VNC Remote Secure services and free ports.
# Works on both Windows (Git Bash/MSYS) and Linux.
set +e

# Ports to free
PORTS="5000 6080 8090 5900 5800 8000"

# Detect OS
detect_os() {
    if [[ -f /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        echo "wsl"
    elif command -v taskkill &>/dev/null; then
        echo "windows"
    else
        echo "linux"
    fi
}

OS_TYPE=$(detect_os)

echo "Stopping VNC Remote Secure services (OS: $OS_TYPE)..."

# Kill by process name
if [[ "$OS_TYPE" == "windows" || "$OS_TYPE" == "wsl" ]]; then
    taskkill /F /IM winvnc.exe 2>/dev/null || true
    # Kill Python processes related to our services
    for proc in web_terminal.py landing_page.py health_web_server.py; do
        pids=$(wmic process where "CommandLine like '%$proc%'" get ProcessId 2>/dev/null | grep -E '^[0-9]+' | tr -d '\r')
        for pid in $pids; do
            taskkill /PID "$pid" /F 2>/dev/null || true
        done
    done
    # Kill websockify
    pids=$(wmic process where "CommandLine like '%websockify%'" get ProcessId 2>/dev/null | grep -E '^[0-9]+' | tr -d '\r')
    for pid in $pids; do
        taskkill /PID "$pid" /F 2>/dev/null || true
    done
else
    # Linux
    pkill -f "web_terminal.py" 2>/dev/null || true
    pkill -f "landing_page.py" 2>/dev/null || true
    pkill -f "health_web_server.py" 2>/dev/null || true
    pkill -f "websockify" 2>/dev/null || true
    pkill -f "tigervncserver" 2>/dev/null || true
    pkill -f "x11vnc" 2>/dev/null || true
fi

# Free ports by killing processes listening on them
for port in $PORTS; do
    if [[ "$OS_TYPE" == "windows" || "$OS_TYPE" == "wsl" ]]; then
        pids=$(netstat -ano 2>/dev/null | grep ":$port " | grep LISTENING | awk '{print $NF}' | tr -d '\r' | sort -u)
        for pid in $pids; do
            taskkill /PID "$pid" /T /F 2>/dev/null || true
        done
    else
        pids=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | sort -u)
        for pid in $pids; do
            kill "$pid" 2>/dev/null || true
        done
        # Fallback with lsof
        pids=$(lsof -ti:"$port" 2>/dev/null)
        for pid in $pids; do
            kill "$pid" 2>/dev/null || true
        done
    fi
done

# Clean up PID files
rm -f /tmp/vnc_remote_*.pid 2>/dev/null

sleep 2
echo "All ports freed: $PORTS"
