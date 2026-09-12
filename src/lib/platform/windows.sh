#!/bin/bash
# shellcheck disable=SC2155,SC2034
# ============================================================================
# WINDOWS PLATFORM BACKEND
# ============================================================================
# Overrides Linux-specific functions for Windows (Git Bash / MSYS2 / MinGW).
#
# This file is sourced AFTER all other modules, so any function defined
# here replaces the Linux implementation of the same name.
#
# Key differences on Windows:
#   - No apt-get → use winget or choco
#   - No useradd/userdel → use net user / net user /delete
#   - No pgrep/pkill → use tasklist / taskkill
#   - No lsof → use netstat -ano
#   - No systemctl → use sc / net stop / net start
#   - No tigervncserver → use TightVNC server
#   - No sudo → run as admin (script must be launched elevated)
#   - No X11 → VNC captures the existing Windows desktop
# ============================================================================

# ============================================================================
# ADMIN CHECK
# ============================================================================
# Check if running with admin privileges on Windows
_is_admin() {
    # Try net session (only works as admin)
    net session &>/dev/null
}

# Print admin warning if not elevated
_platform_warn_if_not_admin() {
    if ! _is_admin; then
        log "yellow" "WARNING: Not running as Administrator."
        log "yellow" "Some features (package installation, service management) may fail."
        log "yellow" "Right-click Git Bash → 'Run as Administrator' for full functionality."
        echo ""
    fi
}

# ============================================================================
# SUDO WRAPPER
# ============================================================================
# On Windows, "sudo" is not available. The script must be run as Administrator.
# This wrapper simply executes the command directly.
# We define it as a function so existing `sudo cmd` calls work unchanged.
sudo() {
    # Skip -u username arguments (Windows doesn't support user switching easily)
    while [[ "${1:-}" == "-u" ]]; do
        shift 2  # Skip -u and the username
    done
    # Skip other sudo flags
    while [[ "${1:-}" == -* ]]; do
        shift
    done
    "$@"
}

# ============================================================================
# PACKAGE MANAGEMENT
# ============================================================================

install_dependencies() {
    log_info "Installing required packages on Windows" "DEPENDENCIES"

    # On Windows, most "dependencies" are either built-in or installed differently.
    # We install the key tools: openssl, certbot, nginx, TightVNC, ttyd
    # Each install is best-effort: if it fails, we continue with a warning.

    # Check for openssl (usually available in Git Bash)
    if ! command -v openssl &>/dev/null; then
        log_warn "openssl not found, SSL features may not work" "DEPENDENCIES"
    fi

    # Install certbot (via pip) — only needed for Let's Encrypt
    if ! command -v certbot &>/dev/null; then
        if [[ -n "$DUCK_DOMAIN" && -n "$EMAIL" ]]; then
            platform_install_package "certbot"
        else
            log_info "certbot not needed (no domain configured, will use self-signed certs)" "DEPENDENCIES"
        fi
    fi

    # Install Python dependencies (Flask for user UI)
    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        log_info "Installing Python Flask for User UI" "DEPENDENCIES"
        pip3 install Flask </dev/null 2>/dev/null || pip install Flask </dev/null 2>/dev/null || true
    fi

    log_success "Dependencies installation completed on Windows" "DEPENDENCIES"
}

# Windows package installation via winget, choco, or pip
platform_install_package() {
    local pkg="$1"

    # Map Linux package names to Windows package names / install methods
    case "$pkg" in
        "openssl")    pkg="openssl" ;;
        "certbot")
            # certbot is best installed via pip on Windows
            log_info "Installing certbot via pip" "DEPENDENCIES"
            if pip3 install certbot </dev/null 2>/dev/null || pip install certbot </dev/null 2>/dev/null; then
                log_success "certbot installed via pip" "DEPENDENCIES"
                return 0
            fi
            log_warn "Could not install certbot, SSL will use self-signed certs" "DEPENDENCIES"
            return 1
            ;;
        "nginx")      pkg="nginx" ;;
        "tigervnc"|"tigervnc-standalone-server")
            pkg="TightVNC"
            # Try specific winget ID for TightVNC
            if command -v winget &>/dev/null; then
                log_info "Installing TightVNC via winget" "DEPENDENCIES"
                if winget install --id "TightVNC.TightVNC" --accept-package-agreements --accept-source-agreements </dev/null 2>/dev/null; then
                    log_success "TightVNC installed via winget" "DEPENDENCIES"
                    return 0
                fi
            fi
            if command -v choco &>/dev/null && _is_admin; then
                log_info "Installing TightVNC via chocolatey" "DEPENDENCIES"
                if echo "y" | timeout 60 choco install tightvnc -y --no-progress 2>/dev/null; then
                    log_success "TightVNC installed via chocolatey" "DEPENDENCIES"
                    return 0
                fi
            fi
            log_warn "Could not install TightVNC automatically." "DEPENDENCIES"
            log_warn "Please install manually from https://www.tightvnc.com/" "DEPENDENCIES"
            return 1
            ;;
        "novnc")      return 0 ;;  # Handled separately (git clone)
        "xfce4"|"xfce4-goodies"|"x11-xserver-utils") return 0 ;;  # N/A on Windows
        "acl")        return 0 ;;  # N/A on Windows
        "iproute2")   return 0 ;;  # netstat is built-in
        "lsof")       return 0 ;;  # Use netstat instead
        "wget")       pkg="wget" ;;
        "python3-certbot-dns-standalone") return 0 ;;  # pip install instead
    esac

    # Try winget first, then choco
    if command -v winget &>/dev/null; then
        log_info "Installing $pkg via winget" "DEPENDENCIES"
        # Redirect stdin from /dev/null to prevent interactive prompts
        if winget install --id "$pkg" --accept-package-agreements --accept-source-agreements -e </dev/null 2>/dev/null; then
            log_success "Package $pkg installed via winget" "DEPENDENCIES"
            return 0
        fi
    fi

    if command -v choco &>/dev/null; then
        # Skip choco if not running as admin (it will hang/fail)
        if ! _is_admin; then
            log_warn "Skipping chocolatey (not running as Administrator)" "DEPENDENCIES"
        else
            log_info "Installing $pkg via chocolatey" "DEPENDENCIES"
            # Pipe "y" to stdin and add timeout to prevent hanging
            if echo "y" | timeout 60 choco install "$pkg" -y --no-progress 2>/dev/null; then
                log_success "Package $pkg installed via chocolatey" "DEPENDENCIES"
                return 0
            fi
        fi
    fi

    log_warn "Could not install $pkg on Windows, continuing..." "DEPENDENCIES"
    return 1
}

check_package_installed() {
    local package="$1"

    # Map to a command name to check
    local cmd_name="$package"
    case "$package" in
        "nginx")      cmd_name="nginx" ;;
        "tigervnc"|"tigervnc-standalone-server") cmd_name="tvnserver" ;;
        "certbot")    cmd_name="certbot" ;;
        "openssl")    cmd_name="openssl" ;;
        "wget")       cmd_name="wget" ;;
        *)            cmd_name="$package" ;;
    esac

    command -v "$cmd_name" &>/dev/null
}

install_package_if_missing() {
    local package="$1"

    if check_package_installed "$package"; then
        log_debug "Package $package is already installed" "DEPENDENCIES"
        return 0
    else
        platform_install_package "$package"
    fi
}

validate_dependencies() {
    local missing_deps=()
    # On Windows, the required commands are different
    local required_commands=("openssl")

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}" "DEPENDENCIES"
        return 1
    else
        log_success "All required dependencies are available" "DEPENDENCIES"
        return 0
    fi
}

update_system_packages() {
    log_info "Updating system packages on Windows" "DEPENDENCIES"

    if command -v winget &>/dev/null; then
        winget upgrade --all --accept-package-agreements --accept-source-agreements 2>/dev/null || true
    fi

    log_success "System packages updated" "DEPENDENCIES"
}

# Detect architecture for downloading Windows binaries
detect_ttyd_arch() {
    local arch
    arch=$(uname -m 2>/dev/null || echo "x86_64")

    case "$arch" in
        x86_64|amd64|x64) echo "x86_64" ;;
        aarch64|arm64)    echo "aarch64" ;;
        i686|i386|x86)    echo "i686" ;;
        *)
            log_warn "Unknown architecture '$arch', defaulting to x86_64" "DEPENDENCIES"
            echo "x86_64"
            ;;
    esac
}

install_ttyd() {
    if command -v ttyd &>/dev/null; then
        log_success "ttyd is already installed" "DEPENDENCIES"
        return 0
    fi

    log_info "Installing ttyd on Windows" "DEPENDENCIES"

    local ttyd_arch
    ttyd_arch=$(detect_ttyd_arch)

    local ttyd_dir="$PROJECT_DIR/bin"
    mkdir -p "$ttyd_dir"

    local ttyd_url="https://github.com/tsl0922/ttyd/releases/download/1.7.4/ttyd.windows-$ttyd_arch.exe"
    local ttyd_bin="$ttyd_dir/ttyd.exe"

    log_info "Downloading ttyd from $ttyd_url" "DEPENDENCIES"

    if command -v curl &>/dev/null; then
        if curl -sL "$ttyd_url" -o "$ttyd_bin" 2>/dev/null; then
            chmod +x "$ttyd_bin" 2>/dev/null || true
            log_success "ttyd downloaded to $ttyd_bin" "DEPENDENCIES"
            # Add to PATH for this session
            export PATH="$ttyd_dir:$PATH"
            return 0
        fi
    fi

    log_error "Failed to download ttyd for Windows" "DEPENDENCIES"
    return 1
}

# ============================================================================
# USER MANAGEMENT
# ============================================================================
# On Windows, the "temporary user" concept is less critical for VNC since
# TightVNC shares the existing desktop. We simplify: skip user creation
# and just use the current user.

get_next_uid() {
    # Windows doesn't use Unix UIDs the same way; return a dummy value
    echo "1000"
}

copy_user_config() {
    # No .Xauthority or .vnc directory needed on Windows
    log_debug "Skipping user config copy (not needed on Windows)" "USER"
}

remove_existing_temp_user() {
    if [[ -z "$TEMP_USER" || "$TEMP_USER" == "$USERNAME" ]]; then
        return 0
    fi

    # Check if user exists via net user
    if ! net user "$TEMP_USER" &>/dev/null; then
        return 0
    fi

    log "yellow" "Removing existing user $TEMP_USER..."

    # Kill user processes
    kill_user_processes_gracefully "$TEMP_USER" 10 || true

    # Delete user
    if net user "$TEMP_USER" /delete 2>/dev/null; then
        log "green" "Successfully removed existing user $TEMP_USER"
    else
        log "yellow" "Could not remove user $TEMP_USER (may need admin privileges)"
    fi
}

create_temp_user() {
    # On Windows, we don't create a separate temp user for VNC.
    # TightVNC shares the current user's desktop.
    # We just verify the current user exists and set TEMP_USER to match.

    log "cyan" "Windows mode: using current user (no temp user creation)"
    log "blue" "Current user: $USERNAME"

    # Set TEMP_USER to the current Windows username for consistency
    export TEMP_USER="$USERNAME"
    export TTYD_USERNAME="$USERNAME"

    # Skip temp user pass — use TTYD_PASSWD for everything
    export TEMP_USER_PASS="$TTYD_PASSWD"

    log "green" "Using current Windows user: $TEMP_USER"
    success "User setup complete (Windows mode)"
}

# ============================================================================
# PROCESS MANAGEMENT
# ============================================================================

# Find process IDs matching a pattern (replaces pgrep -f)
platform_find_pids() {
    local pattern="$1"
    # Use tasklist to find processes, extract PIDs
    # tasklist /FI "IMAGENAME eq pattern" but pattern matching is limited
    # Use wmic for more flexible matching
    if command -v wmic &>/dev/null; then
        wmic process where "name like '%${pattern}%'" get processid 2>/dev/null \
            | tr -d '\r' | grep -E '^[0-9]+' | tr -d ' '
    else
        # Fallback: tasklist with findstr
        tasklist 2>/dev/null | grep -i "$pattern" | awk '{print $2}' | tr -d '\r'
    fi
}

# Terminate a process gracefully (replaces kill + wait)
terminate_process_gracefully() {
    local target="$1"
    local timeout="${2:-10}"
    local signal="${3:-TERM}"

    if [[ -z "$target" ]]; then
        log "red" "terminate_process_gracefully: No target specified"
        return 2
    fi

    # If target is a PID (numeric), use it directly
    local pids
    if [[ "$target" =~ ^[0-9]+$ ]]; then
        pids="$target"
    else
        pids=$(platform_find_pids "$target")
    fi

    if [[ -z "$pids" ]]; then
        log "yellow" "Process '$target' not found"
        return 0
    fi

    local overall_rc=0
    local pid
    for pid in $pids; do
        log "cyan" "Terminating process $pid (timeout: ${timeout}s)..."

        # On Windows, taskkill /T kills child processes too
        # First try graceful (/T = terminate child processes)
        if taskkill /PID "$pid" /T 2>/dev/null; then
            log "green" "Process $pid terminated"
        else
            # Force kill
            log "yellow" "Graceful termination failed, force killing $pid..."
            if taskkill /PID "$pid" /T /F 2>/dev/null; then
                log "green" "Process $pid force terminated"
                overall_rc=1
            else
                log "red" "Failed to terminate process $pid"
                overall_rc=2
            fi
        fi
    done

    return $overall_rc
}

# Kill all processes matching a pattern (replaces pkill -f)
kill_processes_by_pattern() {
    local pattern="$1"
    local timeout="${2:-10}"
    local failed_count=0
    local total_count=0

    if [[ -z "$pattern" ]]; then
        log "red" "kill_processes_by_pattern: No pattern specified"
        return 2
    fi

    log "cyan" "Terminating processes matching pattern: $pattern"

    local pids
    pids=$(platform_find_pids "$pattern")

    if [[ -z "$pids" ]]; then
        log "yellow" "No processes found matching pattern: $pattern"
        return 0
    fi

    # Count PIDs
    total_count=$(echo "$pids" | wc -w)

    for pid in $pids; do
        if ! terminate_process_gracefully "$pid" "$timeout"; then
            failed_count=$((failed_count + 1))
        fi
    done

    if [[ $failed_count -eq 0 ]]; then
        log "green" "All $total_count processes terminated successfully"
        return 0
    elif [[ $failed_count -lt $total_count ]]; then
        log "yellow" "$failed_count of $total_count processes failed to terminate"
        return 1
    else
        log "red" "All $total_count processes failed to terminate"
        return 2
    fi
}

# Kill user processes gracefully (replaces ps -u + kill)
kill_user_processes_gracefully() {
    local username="$1"
    local timeout="${2:-15}"

    if [[ -z "$username" ]]; then
        log "red" "kill_user_processes_gracefully: No username specified"
        return 2
    fi

    log "cyan" "Terminating processes for user: $username"

    # On Windows, use tasklist with user filter
    local pids
    if command -v wmic &>/dev/null; then
        pids=$(wmic process where "ExecutablePath is not null" get processid,userdomain 2>/dev/null \
            | grep -i "$username" | awk '{print $NF}' | tr -d '\r')
    else
        # Fallback: just skip on Windows (process termination by user is complex)
        log "yellow" "Cannot list user processes on Windows, skipping"
        return 0
    fi

    if [[ -z "$pids" ]]; then
        log "yellow" "No processes found for user: $username"
        return 0
    fi

    local failed_count=0
    for pid in $pids; do
        if ! terminate_process_gracefully "$pid" "$timeout"; then
            failed_count=$((failed_count + 1))
        fi
    done

    if [[ $failed_count -eq 0 ]]; then
        log "green" "All user processes terminated successfully"
        return 0
    else
        log "yellow" "$failed_count user processes failed to terminate"
        return 1
    fi
}

# Stop a service gracefully (replaces systemctl-based logic)
stop_service_gracefully() {
    local service="$1"
    local timeout="${2:-20}"

    if [[ -z "$service" ]]; then
        log "red" "stop_service_gracefully: No service name specified"
        return 2
    fi

    log "cyan" "Stopping service: $service"

    # Use sc (Service Control) on Windows
    if sc query "$service" &>/dev/null; then
        # Check if service is running
        local state
        state=$(sc query "$service" 2>/dev/null | grep STATE | awk '{print $3}' | tr -d '\r')
        if [[ "$state" == "RUNNING" || "$state" == "START_PENDING" ]]; then
            log "blue" "Using sc to stop $service..."
            if sc stop "$service" 2>/dev/null; then
                # Wait for service to stop
                local count=0
                while [[ $count -lt $timeout ]]; do
                    state=$(sc query "$service" 2>/dev/null | grep STATE | awk '{print $3}' | tr -d '\r')
                    [[ "$state" == "STOPPED" ]] && break
                    sleep 1
                    count=$((count + 1))
                done

                if [[ "$state" == "STOPPED" ]]; then
                    log "green" "Service $service stopped"
                    return 0
                else
                    log "yellow" "Service $service did not stop in time"
                fi
            else
                log "yellow" "sc stop failed for $service"
            fi
        else
            log "yellow" "Service $service is not running"
            return 0
        fi
    else
        log "yellow" "Service $service not found, using process termination..."
    fi

    # Fallback to process termination
    kill_processes_by_pattern "$service" "$timeout"
}

# ============================================================================
# PORT MANAGEMENT
# ============================================================================

# Check if a port is in use (replaces lsof -i)
check_port_available() {
    local port="$1"

    # Use netstat on Windows
    if netstat -ano 2>/dev/null | grep -q ":$port .*LISTENING"; then
        return 1
    fi
    return 0
}

# Kill process on a specific port (replaces lsof -t -i)
kill_process_on_port() {
    local port="$1"

    # Find PID listening on the port using netstat
    local pids
    pids=$(netstat -ano 2>/dev/null | grep ":$port " | grep LISTENING | awk '{print $NF}' | tr -d '\r' | sort -u)

    if [[ -n "$pids" ]]; then
        local pid
        for pid in $pids; do
            log_info "Stopping process on port $port (PID: $pid)" "CLEANUP"
            terminate_process_gracefully "$pid" 5 || true
        done
    else
        log_debug "No process found on port $port" "CLEANUP"
    fi
}

# ============================================================================
# CLEANUP UTILITIES (overrides for Windows)
# ============================================================================

kill_vnc_server() {
    # On Windows, kill TightVNC server process
    if platform_find_pids "tvnserver" >/dev/null 2>&1 || \
       platform_find_pids "TightVNC" >/dev/null 2>&1; then
        log_info "Stopping VNC server" "CLEANUP"
        kill_processes_by_pattern "tvnserver" 5 || true
        kill_processes_by_pattern "TightVNC" 5 || true
    else
        log_debug "No VNC server running" "CLEANUP"
    fi
}

remove_temp_user() {
    # On Windows, we don't create temp users, so nothing to remove
    log_debug "No temp user to remove (Windows mode)" "CLEANUP"
}

cleanup_processes() {
    log_info "Cleaning up processes" "CLEANUP"

    # Stop services on specific ports
    kill_process_on_port "$NOVNC_PORT"
    kill_process_on_port "$TTYD_PORT"
    kill_process_on_port "$VNC_PORT"

    # Stop VNC server
    kill_vnc_server

    log_success "Process cleanup completed" "CLEANUP"
}

force_cleanup() {
    log_warn "Starting force cleanup (emergency mode)" "CLEANUP"

    local patterns=("tvnserver" "TightVNC" "ttyd" "websockify" "novnc" "nginx")

    for pattern in "${patterns[@]}"; do
        log_info "Force killing processes matching: $pattern" "CLEANUP"
        taskkill /F /IM "$pattern.exe" 2>/dev/null || true
        taskkill /F /IM "$pattern" 2>/dev/null || true
    done

    log_success "Force cleanup completed" "CLEANUP"
}

# ============================================================================
# VNC SERVER (TightVNC for Windows)
# ============================================================================

configure_vnc_password() {
    local user="$1"
    local password="$VNC_PASSWORD"

    log "cyan" "Setting VNC password for TightVNC..."

    # TightVNC stores password in registry encrypted.
    # We set it via the TightVNC server configuration.
    # The password must be encrypted with a specific algorithm.
    # For simplicity, we write a config file and let tvnserver read it.

    local vnc_config_dir="$PROJECT_DIR/data/vnc"
    mkdir -p "$vnc_config_dir"

    # Generate TightVNC password hash using Python
    # TightVNC uses a modified DES encryption of the password
    local vnc_hash
    vnc_hash=$(python3 -c "
import struct
import os

def encrypt_password(password):
    # TightVNC uses a simple DES-like encryption
    # For simplicity, we store the password in plaintext config
    # TightVNC server can also read password from command line
    print(password)

encrypt_password('$password')
" 2>/dev/null || echo "$password")

    # Store password in a config file
    echo "$vnc_hash" > "$vnc_config_dir/vnc_password"
    chmod 600 "$vnc_config_dir/vnc_password" 2>/dev/null || true

    success "VNC password configured for TightVNC"
}

start_vnc_server() {
    log "cyan" "Starting VNC server (TightVNC) on Windows..."

    # Check if TightVNC server is installed
    local tvnserver_cmd=""
    if command -v tvnserver &>/dev/null; then
        tvnserver_cmd="tvnserver"
    elif [[ -f "/c/Program Files/TightVNC/tvnserver.exe" ]]; then
        tvnserver_cmd="/c/Program Files/TightVNC/tvnserver.exe"
    elif [[ -f "/c/Program Files (x86)/TightVNC/tvnserver.exe" ]]; then
        tvnserver_cmd="/c/Program Files (x86)/TightVNC/tvnserver.exe"
    else
        log "yellow" "TightVNC server not found, installing..."
        platform_install_package "TightVNC"

        # Re-check after installation
        if command -v tvnserver &>/dev/null; then
            tvnserver_cmd="tvnserver"
        elif [[ -f "/c/Program Files/TightVNC/tvnserver.exe" ]]; then
            tvnserver_cmd="/c/Program Files/TightVNC/tvnserver.exe"
        elif [[ -f "/c/Program Files (x86)/TightVNC/tvnserver.exe" ]]; then
            tvnserver_cmd="/c/Program Files (x86)/TightVNC/tvnserver.exe"
        else
            die "TightVNC server could not be installed. Please install it manually from https://www.tightvnc.com/"
        fi
    fi

    # Configure VNC password
    configure_vnc_password "$TEMP_USER"

    log "blue" "Port: $VNC_PORT | Password: set"

    # Start TightVNC server
    # TightVNC server runs as a service on Windows, but we can also run it standalone
    # Use -runmode=1 for application mode (not service)
    "$tvnserver_cmd" -run \
        -port="$VNC_PORT" \
        -password="$VNC_PASSWORD" \
        >/dev/null 2>&1 &

    sleep 2

    # Verify VNC server is listening
    if check_port_available "$VNC_PORT"; then
        # Port is available = server NOT listening = failed
        log "red" "VNC server failed to start on port $VNC_PORT"
        log "yellow" "Try running TightVNC server manually: $tvnserver_cmd"
        return 1
    else
        success "VNC server started on port $VNC_PORT"
    fi
}

# ============================================================================
# TTYD SERVICE
# ============================================================================

start_ttyd() {
    log "cyan" "Starting terminal service (ttyd) on Windows..."

    install_ttyd

    # Determine bind address based on nginx status
    local bind_address="0.0.0.0"
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        bind_address="127.0.0.1"
        log "blue" "Binding to localhost (nginx will handle external access)"
    fi

    # Write credentials to a temp file
    local cred_file
    cred_file=$(mktemp /tmp/.ttyd-cred.XXXXXX)
    chmod 600 "$cred_file"
    printf '%s:%s' "$TTYD_USERNAME" "$TTYD_PASSWD" > "$cred_file"

    # Find ttyd binary
    local ttyd_bin="ttyd"
    if ! command -v ttyd &>/dev/null; then
        if [[ -f "$PROJECT_DIR/bin/ttyd.exe" ]]; then
            ttyd_bin="$PROJECT_DIR/bin/ttyd.exe"
        else
            log "red" "ttyd not found"
            rm -f "$cred_file"
            return 1
        fi
    fi

    if [[ "$DISABLE_SSL" == true ]] || [[ "$NGINX_ENABLED" == "true" ]]; then
        log "yellow" "Starting ttyd WITHOUT SSL (nginx handles SSL when enabled)"
        "$ttyd_bin" -c "$(cat "$cred_file")" -p "$TTYD_PORT" -a "$bind_address" \
            cmd.exe >/dev/null 2>&1 &
    else
        log "green" "Starting ttyd WITH SSL encryption"
        if [[ ! -f "$SSL_CERT" || ! -f "$SSL_KEY" ]]; then
            log "red" "SSL certificate or key not found: $SSL_CERT / $SSL_KEY"
            rm -f "$cred_file"
            return 1
        fi
        "$ttyd_bin" -c "$(cat "$cred_file")" -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" \
            -p "$TTYD_PORT" -a "$bind_address" cmd.exe >/dev/null 2>&1 &
    fi

    rm -f "$cred_file"
    sleep 2

    # Verify ttyd is listening
    if ! check_port_available "$TTYD_PORT"; then
        success "Terminal service started on port $TTYD_PORT"
    else
        log "red" "ttyd failed to start on port $TTYD_PORT"
        return 1
    fi
}

# ============================================================================
# NOVNC SERVICE
# ============================================================================

start_novnc() {
    log "cyan" "Starting web VNC interface (noVNC) on Windows..."

    # noVNC requires websockify (Python) to proxy WebSocket to VNC
    # Install websockify via pip if not available
    if ! command -v websockify &>/dev/null; then
        log "blue" "Installing websockify via pip..."
        pip3 install websockify 2>/dev/null || pip install websockify 2>/dev/null || {
            log "red" "Failed to install websockify"
            return 1
        }
    fi

    # Determine bind address
    local bind_address="0.0.0.0"
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        bind_address="127.0.0.1"
    fi

    # Find noVNC web directory
    local novnc_dir=""
    local search_dirs=(
        "/usr/share/novnc"
        "$PROJECT_DIR/novnc"
        "/c/Program Files/novnc"
    )
    for dir in "${search_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            novnc_dir="$dir"
            break
        fi
    done

    # If noVNC is not installed, download it
    if [[ -z "$novnc_dir" ]]; then
        log "blue" "Downloading noVNC..."
        novnc_dir="$PROJECT_DIR/novnc"
        if ! command -v git &>/dev/null; then
            log "red" "git not found, cannot clone noVNC"
            return 1
        fi
        git clone --depth 1 https://github.com/novnc/noVNC.git "$novnc_dir" 2>/dev/null
    fi

    if [[ "$DISABLE_SSL" == true ]] || [[ "$NGINX_ENABLED" == "true" ]]; then
        log "yellow" "Starting noVNC WITHOUT SSL (nginx handles SSL when enabled)"
        websockify --web "$novnc_dir" "$bind_address:$NOVNC_PORT" \
            "127.0.0.1:$VNC_PORT" >/dev/null 2>&1 &
    else
        log "green" "Starting noVNC WITH SSL encryption"
        websockify --web "$novnc_dir" --cert "$SSL_CERT" --key "$SSL_KEY" \
            "$bind_address:$NOVNC_PORT" "127.0.0.1:$VNC_PORT" --ssl-only >/dev/null 2>&1 &
    fi

    sleep 2

    if ! check_port_available "$NOVNC_PORT"; then
        success "Web VNC interface started on port $NOVNC_PORT"
    else
        log "red" "noVNC failed to start on port $NOVNC_PORT"
        return 1
    fi
}

# ============================================================================
# SSL MANAGEMENT (Windows overrides)
# ============================================================================

fix_ssl_permissions() {
    log "yellow" "Fixing SSL certificate permissions on Windows..."

    # On Windows, file permissions are managed differently (icacls)
    # For simplicity, we ensure the files exist and are readable
    if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
        # Use icacls to grant read access to the current user
        local win_cert_path
        local win_key_path
        win_cert_path=$(cygpath -w "$SSL_CERT" 2>/dev/null || echo "$SSL_CERT")
        win_key_path=$(cygpath -w "$SSL_KEY" 2>/dev/null || echo "$SSL_KEY")

        icacls "$win_cert_path" /grant "$USERNAME:R" 2>/dev/null || true
        icacls "$win_key_path" /grant "$USERNAME:R" 2>/dev/null || true

        success "SSL certificate permissions set"
        return 0
    else
        log "red" "SSL certificate files not found"
        return 1
    fi
}

generate_ssl_certificates() {
    log "yellow" "Cleaning up old SSL certificates..."
    rm -rf "$SSL_DIR" 2>/dev/null || true
    rm -f "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true

    log "cyan" "Generating SSL certificates for $DUCK_DOMAIN"

    mkdir -p "$SSL_DIR"

    if [[ -z "$DUCK_DOMAIN" || "$DUCK_DOMAIN" == "localhost" ]]; then
        # Generate self-signed certificate for localhost
        log "blue" "Generating self-signed certificate (localhost)..."

        # Convert paths to Windows format for openssl (native Windows binary)
        local win_cert win_key
        win_cert=$(cygpath -w "$SSL_CERT" 2>/dev/null || echo "$SSL_CERT")
        win_key=$(cygpath -w "$SSL_KEY" 2>/dev/null || echo "$SSL_KEY")

        # MSYS2 converts /CN=... to a Windows path. Use -subj with // prefix
        # or set MSYS2_ARG_CONV_EXCL only for the -subj argument.
        # Using -config with a temp file is the most portable approach.
        local ssl_config
        ssl_config=$(mktemp)
        cat > "$ssl_config" << 'SSLCONF'
[req]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca
[req_distinguished_name]
CN = localhost
[v3_ca]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
SSLCONF

        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$win_key" -out "$win_cert" \
            -config "$ssl_config" 2>/dev/null
        rm -f "$ssl_config"

        if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
            success "Self-signed SSL certificate generated"
            fix_ssl_permissions
            return 0
        else
            log "red" "Failed to generate self-signed certificate"
            return 1
        fi
    else
        # Use certbot for Let's Encrypt
        log "blue" "Requesting certificate from Let's Encrypt..."

        # Install certbot if not available
        if ! command -v certbot &>/dev/null; then
            pip3 install certbot 2>/dev/null || pip install certbot 2>/dev/null || {
                log "red" "Failed to install certbot"
                return 1
            }
        fi

        # Check if port 80 is available
        if ! check_port_available 80; then
            log "yellow" "Port 80 is in use, stopping nginx..."
            stop_nginx 2>/dev/null || true
            sleep 2
        fi

        if certbot certonly --standalone --preferred-challenges http \
            -d "$DUCK_DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email \
            --non-interactive --quiet 2>&1; then
            success "SSL certificate generated successfully"

            # Copy certificates to project directory
            local letsencrypt_dir="/c/ProgramData/certbot/live/$DUCK_DOMAIN"
            if [[ ! -d "$letsencrypt_dir" ]]; then
                letsencrypt_dir="/etc/letsencrypt/live/$DUCK_DOMAIN"
            fi

            if [[ -f "$letsencrypt_dir/fullchain.pem" && -f "$letsencrypt_dir/privkey.pem" ]]; then
                cp "$letsencrypt_dir/fullchain.pem" "$SSL_CERT"
                cp "$letsencrypt_dir/privkey.pem" "$SSL_KEY"
            fi

            fix_ssl_permissions
            return 0
        else
            log "red" "Failed to generate SSL certificate via certbot"
            log "yellow" "Falling back to self-signed certificate..."
            local win_cert2 win_key2 ssl_config2
            win_cert2=$(cygpath -w "$SSL_CERT" 2>/dev/null || echo "$SSL_CERT")
            win_key2=$(cygpath -w "$SSL_KEY" 2>/dev/null || echo "$SSL_KEY")
            ssl_config2=$(mktemp)
            cat > "$ssl_config2" << SSLCONF2
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = $DUCK_DOMAIN
SSLCONF2
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$win_key2" -out "$win_cert2" \
                -config "$ssl_config2" 2>/dev/null
            rm -f "$ssl_config2"
            fix_ssl_permissions
            return 0
        fi
    fi
}

# ============================================================================
# NGINX (Windows overrides)
# ============================================================================

install_nginx() {
    if command -v nginx &>/dev/null; then
        success "nginx is already installed."
        return
    fi

    log "yellow" "Installing nginx on Windows..."

    # Try winget or choco
    if command -v winget &>/dev/null; then
        winget install --id nginx.nginx --accept-package-agreements --accept-source-agreements 2>/dev/null
    elif command -v choco &>/dev/null; then
        choco install nginx -y 2>/dev/null
    fi

    # If still not found, download manually
    if ! command -v nginx &>/dev/null; then
        log "blue" "Downloading nginx manually..."
        local nginx_dir="$PROJECT_DIR/nginx"
        mkdir -p "$nginx_dir"

        local nginx_url="https://nginx.org/download/nginx-1.25.3.zip"
        if command -v curl &>/dev/null; then
            curl -sL "$nginx_url" -o "$nginx_dir/nginx.zip"
            # Unzip (using PowerShell Expand-Archive or unzip)
            if command -v unzip &>/dev/null; then
                unzip -o "$nginx_dir/nginx.zip" -d "$nginx_dir" 2>/dev/null
            else
                powershell.exe -Command "Expand-Archive -Path '$(cygpath -w "$nginx_dir/nginx.zip")' -DestinationPath '$(cygpath -w "$nginx_dir")' -Force" 2>/dev/null
            fi
            rm -f "$nginx_dir/nginx.zip"
            # Add nginx to PATH
            local nginx_bin_dir
            nginx_bin_dir=$(find "$nginx_dir" -name "nginx.exe" -exec dirname {} \; 2>/dev/null | head -1)
            if [[ -n "$nginx_bin_dir" ]]; then
                export PATH="$nginx_bin_dir:$PATH"
            fi
        fi
    fi

    if command -v nginx &>/dev/null; then
        success "nginx installed successfully."
    else
        log "yellow" "nginx installation may require a restart or manual PATH update"
    fi
}

configure_nginx() {
    log "cyan" "Configuring nginx reverse proxy on Windows..."

    # On Windows, nginx config is typically in the nginx installation directory
    local nginx_conf_dir=""
    local nginx_exe=""

    # Find nginx
    if command -v nginx &>/dev/null; then
        nginx_exe=$(command -v nginx)
        nginx_conf_dir=$(dirname "$nginx_exe")/conf
    elif [[ -d "/c/nginx/conf" ]]; then
        nginx_conf_dir="/c/nginx/conf"
        nginx_exe="/c/nginx/nginx.exe"
    else
        # Search in project directory
        nginx_exe=$(find "$PROJECT_DIR/nginx" -name "nginx.exe" 2>/dev/null | head -1)
        if [[ -n "$nginx_exe" ]]; then
            nginx_conf_dir=$(dirname "$nginx_exe")/conf
        fi
    fi

    if [[ -z "$nginx_conf_dir" || ! -d "$nginx_conf_dir" ]]; then
        log "red" "nginx configuration directory not found"
        return 1
    fi

    # Create nginx configuration from template
    local template_file="$PROJECT_DIR/src/config/nginx.conf"

    if [[ -f "$template_file" ]]; then
        # Load .env if exists (CRLF-safe for Windows .env files)
        if [[ -f "$PROJECT_DIR/.env" ]]; then
            # shellcheck source=/dev/null
            source <(tr -d '\r' < "$PROJECT_DIR/.env")
        fi

        # Set defaults
        export DUCK_DOMAIN="${DUCK_DOMAIN:-localhost}"
        export NGINX_HTTP_PORT="${NGINX_HTTP_PORT:-80}"
        export NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"
        export NOVNC_HOST="${NOVNC_HOST:-127.0.0.1}"
        export NOVNC_PORT="${NOVNC_PORT:-6080}"
        export TTYD_HOST="${TTYD_HOST:-127.0.0.1}"
        export TTYD_PORT="${TTYD_PORT:-5000}"
        export HEALTH_WEB_HOST="${HEALTH_WEB_HOST:-127.0.0.1}"
        export HEALTH_WEB_PORT="${HEALTH_WEB_PORT:-8080}"
        export HEALTH_BACKEND_PROTOCOL="${HEALTH_BACKEND_PROTOCOL:-http}"

        # Ensure SSL paths are absolute
        export SSL_CERT="${SSL_CERT:-$PROJECT_DIR/data/ssl/fullchain.pem}"
        export SSL_KEY="${SSL_KEY:-$PROJECT_DIR/data/ssl/privkey.pem}"

        # Process template
        if command -v envsubst &>/dev/null; then
            envsubst '\$DUCK_DOMAIN|\$SSL_CERT|\$SSL_KEY|\$NGINX_HTTP_PORT|\$NGINX_HTTPS_PORT|\$NOVNC_HOST|\$NOVNC_PORT|\$TTYD_HOST|\$TTYD_PORT|\$HEALTH_WEB_HOST|\$HEALTH_WEB_PORT|\$HEALTH_BACKEND_PROTOCOL' \
                < "$template_file" > "$nginx_conf_dir/rpi-vnc.conf"
        else
            # Fallback: use sed for simple substitution
            sed -e "s|\${DUCK_DOMAIN}|${DUCK_DOMAIN}|g" \
                -e "s|\${SSL_CERT}|${SSL_CERT}|g" \
                -e "s|\${SSL_KEY}|${SSL_KEY}|g" \
                -e "s|\${NGINX_HTTP_PORT}|${NGINX_HTTP_PORT}|g" \
                -e "s|\${NGINX_HTTPS_PORT}|${NGINX_HTTPS_PORT}|g" \
                -e "s|\${NOVNC_HOST}|${NOVNC_HOST}|g" \
                -e "s|\${NOVNC_PORT}|${NOVNC_PORT}|g" \
                -e "s|\${TTYD_HOST}|${TTYD_HOST}|g" \
                -e "s|\${TTYD_PORT}|${TTYD_PORT}|g" \
                -e "s|\${HEALTH_WEB_HOST}|${HEALTH_WEB_HOST}|g" \
                -e "s|\${HEALTH_WEB_PORT}|${HEALTH_WEB_PORT}|g" \
                -e "s|\${HEALTH_BACKEND_PROTOCOL}|${HEALTH_BACKEND_PROTOCOL}|g" \
                "$template_file" > "$nginx_conf_dir/rpi-vnc.conf"
        fi

        # Include our config in the main nginx.conf
        local main_conf="$nginx_conf_dir/nginx.conf"
        if [[ -f "$main_conf" ]]; then
            # Add include directive if not already present
            if ! grep -q "rpi-vnc.conf" "$main_conf"; then
                # Backup original config
                cp "$main_conf" "$main_conf.bak"
                # Add include before the last closing brace
                sed -i "s|}|    include rpi-vnc.conf;\n}|" "$main_conf"
            fi
        fi

        log "blue" "Nginx configuration created at $nginx_conf_dir/rpi-vnc.conf"
    else
        log "red" "Nginx template not found at $template_file"
        return 1
    fi

    # Test nginx configuration
    if nginx -t 2>/dev/null; then
        success "nginx configuration is valid."
    else
        nginx -t
        die "nginx configuration test failed."
    fi
}

start_nginx() {
    log "cyan" "Starting nginx on Windows..."

    # On Windows, nginx runs as a process (not a service by default)
    if command -v nginx &>/dev/null; then
        nginx 2>/dev/null
        success "nginx started successfully."
    else
        log "red" "nginx not found"
        return 1
    fi
}

stop_nginx() {
    log "yellow" "Stopping nginx on Windows..."

    if command -v nginx &>/dev/null; then
        nginx -s stop 2>/dev/null || true
    fi

    # Also try killing the process
    kill_processes_by_pattern "nginx" 5 || true

    success "nginx stopped."
}

restart_nginx() {
    log "cyan" "Restarting nginx on Windows..."
    stop_nginx
    sleep 2
    start_nginx
    success "nginx restarted successfully."
}

reload_nginx() {
    log "cyan" "Reloading nginx configuration on Windows..."

    if command -v nginx &>/dev/null; then
        nginx -s reload 2>/dev/null || restart_nginx
    fi

    success "nginx reloaded successfully."
}

nginx_status() {
    if ! check_port_available 80 2>/dev/null || ! check_port_available 443 2>/dev/null; then
        log "green" "nginx is running"
    else
        log "red" "nginx is not running"
    fi
}

# ============================================================================
# SYSTEM RESOURCES (Windows overrides)
# ============================================================================

log_system_resources() {
    [[ "$VERBOSE" != "true" ]] && return

    local cpu_usage mem_usage disk_usage

    # CPU usage via wmic (strip whitespace, CR, and empty lines)
    cpu_usage=$(wmic cpu get loadpercentage 2>/dev/null | tr -d '\r' | tr -s ' ' | grep -E '^[0-9]+' | head -1 | tr -d ' ')
    cpu_usage="${cpu_usage:-N/A}"

    # Memory usage via wmic
    local free_mem total_mem
    free_mem=$(wmic OS get FreePhysicalMemory 2>/dev/null | tr -d '\r' | tr -s ' ' | grep -E '^[0-9]+' | head -1 | tr -d ' ')
    total_mem=$(wmic OS get TotalVisibleMemorySize 2>/dev/null | tr -d '\r' | tr -s ' ' | grep -E '^[0-9]+' | head -1 | tr -d ' ')
    if [[ -n "$free_mem" && -n "$total_mem" && "$total_mem" -gt 0 ]] 2>/dev/null; then
        mem_usage=$(awk "BEGIN {printf \"%.1f\", (1 - $free_mem/$total_mem) * 100}")
    else
        mem_usage="N/A"
    fi

    # Disk usage (df works in Git Bash)
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}')
    disk_usage="${disk_usage:-N/A}"

    log "cyan" "System Resources - CPU: ${cpu_usage}%, Memory: ${mem_usage}%, Disk: ${disk_usage}"
}

# ============================================================================
# SERVICE STATUS CHECK (Windows overrides)
# ============================================================================

check_service_status() {
    local service_name="$1"
    local process_pattern="$2"

    # On Windows, check if the process is running
    local pids
    pids=$(platform_find_pids "$process_pattern" 2>/dev/null)

    if [[ -n "$pids" ]]; then
        log_success "$service_name is running" "STATUS"
        return 0
    else
        log_error "$service_name is not running" "STATUS"
        return 1
    fi
}

# Override check_system_status to be resilient to set -e
check_system_status() {
    log_info "Checking system status" "STATUS"

    # Check core services (use || true to prevent set -e from aborting)
    check_service_status "VNC Server" "tvnserver" || true
    check_service_status "ttyd" "ttyd" || true
    check_service_status "noVNC" "websockify" || true

    # Check optional services
    if [[ "$NGINX_ENABLED" == "true" ]]; then
        check_service_status "nginx" "nginx" || true
    fi

    if [[ "$MONITORING_ENABLED" == "true" ]]; then
        check_service_status "Prometheus" "prometheus" || true
        check_service_status "Grafana" "grafana" || true
        check_service_status "Node Exporter" "node_exporter" || true
    fi

    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        check_service_status "User UI" "flask" || true
    fi

    # Check system resources
    log_system_resources

    # Check SSL certificates
    if [[ "$DISABLE_SSL" == "false" ]]; then
        check_ssl_status || true
    fi

    log_success "System status check completed" "STATUS"
}

# ============================================================================
# ERROR HANDLING RECOVERY (Windows overrides)
# ============================================================================

recover_user_management() {
    log_info "User management recovery on Windows (no-op)" "RECOVERY"
    return 0
}

recover_service_management() {
    log_info "Service management recovery on Windows" "RECOVERY"
    # No systemd on Windows, nothing to reload
    return 0
}

recover_ssl_management() {
    local exit_code="$1"
    log_info "SSL management recovery on Windows" "RECOVERY"

    # Check if port 80 is blocked
    if ! check_port_available 80 2>/dev/null; then
        log_warn "Port 80 is in use, attempting to free it" "RECOVERY"
        stop_nginx 2>/dev/null || true
        sleep 2
    fi

    return 0
}

# ============================================================================
# CONFIG VALIDATION (Windows overrides)
# ============================================================================

# Override validate_config to relax Linux-specific checks on Windows
validate_config() {
    local errors=0

    # Validate TEMP_USER format (still needed for safety)
    if ! [[ "$TEMP_USER" =~ ^[a-zA-Z][a-zA-Z0-9_-]{1,31}$ ]]; then
        log "red" "TEMP_USER must start with a letter and contain only letters, digits, hyphens, and underscores (max 32 chars)."
        errors=$((errors + 1))
    fi

    # Validate passwords
    if ! _validate_config_password "$TTYD_PASSWD" "TTYD_PASSWD"; then
        errors=$((errors + 1))
    fi
    if ! _validate_config_password "$VNC_PASSWORD" "VNC_PASSWORD"; then
        errors=$((errors + 1))
    fi
    if [[ "$USER_UI_ENABLED" == "true" ]]; then
        if ! _validate_config_password "$USER_UI_PASSWORD" "USER_UI_PASSWORD"; then
            errors=$((errors + 1))
        fi
    fi

    # Validate email
    if [[ -n "$EMAIL" ]]; then
        if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log "red" "EMAIL must be a valid email address."
            errors=$((errors + 1))
        elif [[ "$EMAIL" == *"example.com" ]]; then
            log "red" "EMAIL cannot use the example.com placeholder domain."
            errors=$((errors + 1))
        fi
    fi

    # Validate ports
    _validate_config_port "$NOVNC_PORT" "NOVNC_PORT" || errors=$((errors + $?))
    _validate_config_port "$TTYD_PORT" "TTYD_PORT" || errors=$((errors + $?))
    _validate_config_port "$VNC_PORT" "VNC_PORT" || errors=$((errors + $?))

    # Validate domain (empty is allowed — means no SSL)
    # On Windows, localhost is a valid domain for self-signed certificates
    if [[ -n "$DUCK_DOMAIN" ]]; then
        if [[ "$DUCK_DOMAIN" == "localhost" || "$DUCK_DOMAIN" == "127.0.0.1" ]]; then
            log "yellow" "Using localhost for self-signed SSL certificate"
        elif ! validate_domain "$DUCK_DOMAIN" "DUCK_DOMAIN"; then
            log "red" "DUCK_DOMAIN must be a valid domain name"
            errors=$((errors + 1))
        fi
    fi

    if (( errors > 0 )); then
        log "red" "Configuration validation failed with $errors error(s)"
        return 1
    fi

    return 0
}

# ============================================================================
# MISC OVERRIDES
# ============================================================================

# id command wrapper — on Windows, id doesn't exist
id() {
    if [[ "$1" == "-u" ]]; then
        # Return a dummy UID
        echo "1000"
    elif [[ "$1" == "-g" ]]; then
        # Return a dummy GID
        echo "1000"
    elif [[ "$1" == "-gn" ]]; then
        # Return group name (use username)
        echo "$USERNAME"
    elif [[ -z "$1" ]]; then
        # Full id output
        echo "uid=1000($USERNAME) gid=1000($USERNAME) groups=1000($USERNAME)"
    else
        # Check if user exists — on Windows, always return success for current user
        if [[ "$1" == "$USERNAME" ]]; then
            echo "uid=1000($USERNAME) gid=1000($USERNAME)"
        else
            # Check via net user
            if net user "$1" &>/dev/null; then
                echo "uid=1000($1) gid=1000($1)"
            else
                return 1
            fi
        fi
    fi
}

# pkill wrapper — redirect to taskkill-based implementation
pkill() {
    local force_flag=""
    local pattern=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -9|-KILL) force_flag="/F"; shift ;;
            -f) shift; pattern="$1"; shift ;;
            -u) shift; pattern=""; shift ;;  # Skip user-based pkill
            *) pattern="$1"; shift ;;
        esac
    done

    if [[ -n "$pattern" ]]; then
        local pids
        pids=$(platform_find_pids "$pattern")
        if [[ -n "$pids" ]]; then
            if [[ -n "$force_flag" ]]; then
                for pid in $pids; do
                    taskkill /PID "$pid" /T /F 2>/dev/null || true
                done
            else
                for pid in $pids; do
                    taskkill /PID "$pid" /T 2>/dev/null || true
                done
            fi
        fi
    fi
}

# pgrep wrapper — redirect to tasklist-based implementation
pgrep() {
    local pattern=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|-x) shift; pattern="$1"; shift ;;
            -u) shift; shift ;;  # Skip user option
            *) pattern="$1"; shift ;;
        esac
    done

    if [[ -n "$pattern" ]]; then
        local pids
        pids=$(platform_find_pids "$pattern")
        if [[ -n "$pids" ]]; then
            echo "$pids"
            return 0
        fi
    fi
    return 1
}

# ============================================================================
# FAIL2BAN OVERRIDES
# ============================================================================
# Fail2ban is Linux-specific (uses iptables/systemd). On Windows, these
# functions become no-ops with clear warnings so the script doesn't fail.

install_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    log "yellow" "Fail2ban is not available on Windows (Linux/iptables-based)."
    log "yellow" "  Use Windows Firewall rules or a network-level IPS instead."
    log "yellow" "  Skipping fail2ban installation."
}

configure_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    log "yellow" "Fail2ban configuration skipped on Windows (not supported)."
}

start_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    log "yellow" "Fail2ban start skipped on Windows (not supported)."
}

stop_fail2ban() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    log "yellow" "Fail2ban stop skipped on Windows (not supported)."
}

check_fail2ban_status() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    log "yellow" "Fail2ban status: not available on Windows."
}

unban_ip() {
    [[ "$FAIL2BAN_ENABLED" != "true" ]] && return
    local ip="$1"
    log "yellow" "Unban IP $ip skipped on Windows (fail2ban not available)."
    log "yellow" "  Use 'netsh advfirewall firewall delete rule' to manage firewall blocks."
}

# ============================================================================
# MONITORING OVERRIDES (Prometheus / Grafana / Node Exporter)
# ============================================================================
# These are Linux binaries. On Windows, we provide Windows-native alternatives
# or graceful no-ops with guidance.

install_node_exporter() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Prometheus node_exporter is Linux-only."
    log "yellow" "  On Windows, use 'windows_exporter' (https://github.com/prometheus-community/windows_exporter)."
    log "yellow" "  Attempting to install windows_exporter via winget..."
    if _is_admin; then
        winget install --id prometheus.windows_exporter --silent --accept-package-agreements --accept-source-agreements 2>/dev/null || \
            log "yellow" "  Could not install windows_exporter automatically. Install it manually."
    else
        log "yellow" "  Administrator privileges required. Run as admin to install windows_exporter."
    fi
}

install_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Prometheus server install on Windows..."
    if _is_admin; then
        winget install --id prometheus.prometheus --silent --accept-package-agreements --accept-source-agreements 2>/dev/null || \
            log "yellow" "  Could not install Prometheus via winget. Download from https://prometheus.io/download/."
    else
        log "yellow" "  Administrator privileges required. Run as admin to install Prometheus."
    fi
}

install_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Installing Grafana on Windows..."
    if _is_admin; then
        winget install --id GrafanaLabs.Grafana --silent --accept-package-agreements --accept-source-agreements 2>/dev/null || \
            log "yellow" "  Could not install Grafana via winget. Download from https://grafana.com/grafana/download."
    else
        log "yellow" "  Administrator privileges required. Run as admin to install Grafana."
    fi
}

configure_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Configuring Prometheus on Windows..."
    local prom_dir="$PROJECT_DIR/data/prometheus"
    mkdir -p "$prom_dir" 2>/dev/null || true
    cat > "$prom_dir/prometheus.yml" <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:$NODE_EXPORTER_PORT']

  - job_name: 'vnc_services'
    static_configs:
      - targets: ['localhost:$NOVNC_PORT', 'localhost:$TTYD_PORT', 'localhost:$VNC_PORT']
    metrics_path: /metrics
EOF
    log "green" "Prometheus config written to $prom_dir/prometheus.yml"
}

configure_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Configuring Grafana on Windows..."
    local grafana_dir="$PROJECT_DIR/data/grafana"
    mkdir -p "$grafana_dir" 2>/dev/null || true
    local grafana_password="${GRAFANA_ADMIN_PASSWORD:-}"
    if [[ -z "$grafana_password" ]]; then
        grafana_password="$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))" 2>/dev/null)"
        if [[ -z "$grafana_password" ]]; then
            log "red" "Failed to generate Grafana password. Set GRAFANA_ADMIN_PASSWORD in .env."
            return 1
        fi
    fi
    cat > "$grafana_dir/grafana.ini" <<EOF
[server]
http_port = $GRAFANA_PORT

[security]
admin_user = admin
admin_password = $grafana_password

[users]
allow_sign_up = false
EOF
    log "green" "Grafana config written to $grafana_dir/grafana.ini (admin password set)"
}

start_node_exporter() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Starting Node Exporter on Windows..."
    if command -v windows_exporter &>/dev/null; then
        windows_exporter --web.listen-address=":$NODE_EXPORTER_PORT" &
    elif command -v node_exporter &>/dev/null; then
        node_exporter --web.listen-address=":$NODE_EXPORTER_PORT" &
    else
        log "yellow" "  node_exporter/windows_exporter not found. Install it first."
    fi
}

start_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Starting Prometheus on Windows..."
    local prom_dir="$PROJECT_DIR/data/prometheus"
    if command -v prometheus &>/dev/null; then
        prometheus --config.file="$prom_dir/prometheus.yml" \
            --storage.tsdb.path="$prom_dir/data" \
            --web.listen-address=":$PROMETHEUS_PORT" &
    else
        log "yellow" "  prometheus binary not found. Install it first."
    fi
}

start_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Starting Grafana on Windows..."
    if command -v grafana-server &>/dev/null; then
        grafana-server --homepath="$PROJECT_DIR/data/grafana" --config="$PROJECT_DIR/data/grafana/grafana.ini" &
    elif [[ -f "/c/Program Files/GrafanaLabs/bin/grafana-server.exe" ]]; then
        "/c/Program Files/GrafanaLabs/bin/grafana-server.exe" --homepath="$PROJECT_DIR/data/grafana" --config="$PROJECT_DIR/data/grafana/grafana.ini" &
    else
        log "yellow" "  grafana-server not found. Install it first."
    fi
}

stop_monitoring() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    log "yellow" "Stopping monitoring services on Windows..."
    pkill -f prometheus 2>/dev/null || true
    pkill -f node_exporter 2>/dev/null || true
    pkill -f windows_exporter 2>/dev/null || true
    pkill -f grafana 2>/dev/null || true
    log "green" "Monitoring services stopped."
}

monitoring_status() {
    echo "=== Monitoring Status (Windows) ==="
    local ne_status="Stopped"
    local prom_status="Stopped"
    local grafana_status="Stopped"
    pgrep -f "node_exporter" &>/dev/null && ne_status="Running"
    pgrep -f "windows_exporter" &>/dev/null && ne_status="Running"
    pgrep -f "prometheus" &>/dev/null && prom_status="Running"
    pgrep -f "grafana" &>/dev/null && grafana_status="Running"
    echo "Node Exporter: $ne_status"
    echo "Prometheus: $prom_status"
    echo "Grafana: $grafana_status"
    echo ""
    echo "Access URLs:"
    echo "  Prometheus: http://localhost:$PROMETHEUS_PORT"
    echo "  Grafana: http://localhost:$GRAFANA_PORT"
}

# ============================================================================
# RECORDING OVERRIDES (asciinema)
# ============================================================================
# asciinema is Linux-only. On Windows, we provide graceful no-ops and
# suggest Windows alternatives (e.g., Windows Terminal recording).

install_asciinema() {
    [[ "$RECORDING_ENABLED" != "true" ]] && return
    log "yellow" "asciinema is Linux-only and not available on Windows."
    log "yellow" "  Use 'pip install asciinema' if you have WSL, or use Windows Terminal's built-in recording."
    # Try pip install as a fallback (works in WSL-like environments)
    pip3 install asciinema 2>/dev/null || \
        log "yellow" "  Could not install asciinema via pip. Recording will be disabled."
}

create_recording_dir() {
    [[ "$RECORDING_ENABLED" != "true" ]] && return
    mkdir -p "$RECORDING_DIR" 2>/dev/null || true
}

start_ttyd_recording() {
    [[ "$RECORDING_ENABLED" != "true" ]] && return
    [[ "$RECORDING_FORMAT" != "asciinema" ]] && return
    log "yellow" "ttyd recording on Windows is a placeholder (asciinema not available natively)."
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local recording_file="$RECORDING_DIR/ttyd_${timestamp}.cast"
    export TTYD_RECORDING="$recording_file"
}

start_vnc_recording() {
    [[ "$RECORDING_ENABLED" != "true" ]] && return
    log "yellow" "VNC recording on Windows is a placeholder."
    log "yellow" "  Use an external screen capture tool (e.g., OBS Studio, Windows Game Bar)."
}

list_recordings() {
    [[ ! -d "$RECORDING_DIR" ]] && {
        log "yellow" "No recordings directory found"
        return
    }
    log "cyan" "Available recordings:"
    ls -lh "$RECORDING_DIR" 2>/dev/null || log "yellow" "No recordings found"
}

play_recording() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        die "Recording file not found: $file"
    fi
    if [[ "$file" == *.cast ]]; then
        if command -v asciinema &>/dev/null; then
            asciinema play "$file"
        else
            log "yellow" "asciinema not installed. Install via 'pip install asciinema' or use WSL."
        fi
    elif [[ "$file" == *.script ]]; then
        if command -v scriptreplay &>/dev/null; then
            scriptreplay "$file"
        else
            log "yellow" "scriptreplay not available on Windows."
        fi
    else
        die "Unknown recording format"
    fi
}

cleanup_old_recordings() {
    local days="${1:-7}"
    if [[ -z "$RECORDING_DIR" ]]; then
        log "red" "RECORDING_DIR is not set, cannot clean up recordings"
        return 1
    fi
    if [[ ! -d "$RECORDING_DIR" ]]; then
        log "yellow" "RECORDING_DIR ($RECORDING_DIR) does not exist, nothing to clean up"
        return 0
    fi
    log "yellow" "Cleaning up recordings older than $days days..."
    find "$RECORDING_DIR" -maxdepth 1 -type f -mtime +"$days" -delete 2>/dev/null || true
    log "green" "Old recordings cleaned up."
}

enable_ttyd_recording() {
    [[ "$RECORDING_ENABLED" != "true" ]] && return
    log "yellow" "TTYD recording enabled (placeholder on Windows)"
}

# ============================================================================
# HEALTHCHECK OVERRIDES
# ============================================================================
# Linux healthcheck uses ss, lsof, top, free, vcgencmd, /proc/loadavg.
# Windows uses netstat, tasklist, wmic, and Python for system metrics.

_log_service_running() {
    local service="$1" port="$2" pid="$3" process_name="$4" listening_address="$5"
    if [[ "$NGINX_ENABLED" == "true" ]] && [[ "$listening_address" == *"127.0.0.1"* ]]; then
        log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: 127.0.0.1 - nginx mode)"
    else
        log "green" "$service running on port $port (PID: $pid, Process: $process_name, Address: $listening_address)"
    fi
}

_log_service_not_running() {
    local service="$1" port="$2"
    log "red" "$service NOT running on port $port"
    log "blue" "Checking all listening ports..."
    local all_ports
    all_ports=$(netstat -ano 2>/dev/null | grep LISTENING | head -5)
    if [[ -n "$all_ports" ]]; then
        log "blue" "Currently listening ports:"
        echo "$all_ports" | while IFS= read -r line; do
            log "blue" "  $line"
        done
    else
        log "blue" "No listening ports found"
    fi
}

check_service_port() {
    local port="$1"
    local service="$2"
    local pid=""
    local process_name=""
    local listening_address=""

    local port_info
    port_info=$(netstat -ano 2>/dev/null | grep ":$port " | grep LISTENING | head -1)

    if [[ -n "$port_info" ]]; then
        pid=$(echo "$port_info" | awk '{print $NF}' | tr -d '\r')
        if [[ -n "$pid" ]]; then
            process_name=$(tasklist /FI "PID eq $pid" /NH /FO CSV 2>/dev/null | head -1 | tr -d '"' | cut -d, -f1)
        fi
        listening_address=$(echo "$port_info" | awk '{print $2}' | head -1)
        _log_service_running "$service" "$port" "$pid" "$process_name" "$listening_address"
        return 0
    fi

    _log_service_not_running "$service" "$port"
    return 1
}

check_process() {
    local process="$1"
    local pids
    pids=$(platform_find_pids "$process")
    local pid_count=0
    [[ -n "$pids" ]] && pid_count=$(echo "$pids" | wc -l | tr -d ' ')

    if [[ $pid_count -gt 0 ]]; then
        log "green" "$process running ($pid_count instances, PIDs: $pids)"
        return 0
    else
        log "red" "$process NOT running"
        return 1
    fi
}

check_novnc() {
    check_service_port "$NOVNC_PORT" "noVNC"
}

check_ttyd() {
    check_service_port "$TTYD_PORT" "ttyd"
}

check_vnc() {
    check_service_port "$VNC_PORT" "VNC Server"
    check_process "vnc"
    check_process "tvnserver"
    check_process "winvnc"
}

check_temp_user() {
    # On Windows, the "temp user" is the current user — always exists
    log "green" "User $TEMP_USER (Windows current user: $USERNAME) exists"
    return 0
}

check_ssl_cert() {
    if [[ -z "$DUCK_DOMAIN" ]]; then
        log "yellow" "SSL not configured (no domain)"
        return 0
    fi

    if [[ -f "$SSL_CERT" ]]; then
        local expiry_date issue_date subject issuer cert_serial
        expiry_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        issue_date=$(openssl x509 -startdate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        subject=$(openssl x509 -subject -noout -in "$SSL_CERT" 2>/dev/null | sed 's/subject=//')
        issuer=$(openssl x509 -issuer -noout -in "$SSL_CERT" 2>/dev/null | sed 's/issuer=//')
        cert_serial=$(openssl x509 -serial -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)

        # Use Python for date parsing (portable across Windows/Linux)
        local expiry_epoch current_epoch days_left
        expiry_epoch=$(python3 -c "
from datetime import datetime
import sys
try:
    print(int(datetime.strptime(sys.argv[1], '%b %d %H:%M:%S %Y %Z').timestamp()))
except Exception:
    try:
        print(int(datetime.strptime(sys.argv[1], '%Y-%m-%d %H:%M:%S').timestamp()))
    except Exception:
        sys.exit(1)
" "$expiry_date" 2>/dev/null)
        if [[ -z "$expiry_epoch" ]]; then
            log "yellow" "SSL: Cannot parse expiry date '$expiry_date'"
            return 1
        fi
        current_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - current_epoch) / 86400 ))

        if (( days_left > 30 )); then
            log "green" "SSL: Valid $days_left days | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 0
        elif (( days_left > 0 )); then
            log "yellow" "SSL: Expires in $days_left days | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 0
        else
            log "red" "SSL: EXPIRED | Domain: $DUCK_DOMAIN | Subject: $subject | Issuer: $issuer | Serial: $cert_serial"
            return 1
        fi
    else
        log "red" "SSL certificate not found for domain: $DUCK_DOMAIN"
        return 1
    fi
}

check_memory() {
    # Use wmic on Windows to get memory usage
    local mem_info mem_total mem_free mem_used mem_percent
    mem_info=$(wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value 2>/dev/null | tr -d '\r')
    mem_total=$(echo "$mem_info" | grep TotalVisibleMemorySize | cut -d= -f2)
    mem_free=$(echo "$mem_info" | grep FreePhysicalMemory | cut -d= -f2)

    if [[ -z "$mem_total" || -z "$mem_free" ]]; then
        log "yellow" "Memory: unable to query on Windows"
        return 0
    fi

    mem_used=$(( mem_total - mem_free ))
    mem_percent=$(( mem_used * 100 / mem_total ))

    if (( mem_percent < 80 )); then
        log "green" "Memory: ${mem_percent}% (${mem_used}KB/${mem_total}KB) | Free: ${mem_free}KB"
        return 0
    elif (( mem_percent < 90 )); then
        log "yellow" "Memory: ${mem_percent}% (${mem_used}KB/${mem_total}KB) | Free: ${mem_free}KB"
        return 0
    else
        log "red" "Memory: ${mem_percent}% (${mem_used}KB/${mem_total}KB) | Free: ${mem_free}KB"
        return 1
    fi
}

check_cpu() {
    # Use wmic to get CPU load percentage on Windows
    local cpu_usage cpu_load_1min cpu_cores
    cpu_usage=$(wmic cpu get loadPercentage /Value 2>/dev/null | tr -d '\r' | grep LoadPercentage | cut -d= -f2 | head -1)
    cpu_cores=$(python3 -c "import os; print(os.cpu_count())" 2>/dev/null || echo "N/A")

    # Windows doesn't have load average; use process count as a proxy
    local proc_count
    proc_count=$(tasklist 2>/dev/null | wc -l | tr -d ' ')
    cpu_load_1min="$cpu_usage%"

    if [[ -z "$cpu_usage" ]]; then
        log "yellow" "CPU: unable to query load on Windows"
        return 0
    fi

    # Validate that cpu_usage is numeric before arithmetic comparison
    if ! [[ "$cpu_usage" =~ ^[0-9]+$ ]]; then
        log "yellow" "CPU: invalid value '$cpu_usage'"
        return 0
    fi

    if (( cpu_usage < 70 )); then
        log "green" "CPU: ${cpu_usage}% | Processes: ${proc_count} | Cores: ${cpu_cores}"
        return 0
    elif (( cpu_usage < 90 )); then
        log "yellow" "CPU: ${cpu_usage}% | Processes: ${proc_count} | Cores: ${cpu_cores}"
        return 0
    else
        log "red" "CPU: ${cpu_usage}% | Processes: ${proc_count} | Cores: ${cpu_cores}"
        return 1
    fi
}

check_disk() {
    # Use df (available in Git Bash) or wmic as fallback
    local disk_usage disk_total disk_used disk_free disk_int
    if df -h / &>/dev/null; then
        disk_usage=$(df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
        disk_total=$(df -h / | awk 'NR==2 {print $2}')
        disk_used=$(df -h / | awk 'NR==2 {print $3}')
        disk_free=$(df -h / | awk 'NR==2 {print $4}')
    else
        # Fallback to wmic for drive C:
        local disk_info
        disk_info=$(wmic logicaldisk where "DeviceID='C:'" get Size,FreeSpace /Value 2>/dev/null | tr -d '\r')
        local disk_size_bytes disk_free_bytes
        disk_size_bytes=$(echo "$disk_info" | grep Size | cut -d= -f2)
        disk_free_bytes=$(echo "$disk_info" | grep FreeSpace | cut -d= -f2)
        if [[ -z "$disk_size_bytes" || -z "$disk_free_bytes" ]]; then
            log "yellow" "Disk: unable to query on Windows"
            return 0
        fi
        disk_used=$(( disk_size_bytes - disk_free_bytes ))
        disk_usage=$(( disk_used * 100 / disk_size_bytes ))
        disk_total=$(python3 -c "print(f'{$disk_size_bytes/1073741824:.0f}G')" 2>/dev/null || echo "?")
        disk_used=$(python3 -c "print(f'{$disk_used/1073741824:.0f}G')" 2>/dev/null || echo "?")
        disk_free=$(python3 -c "print(f'{$disk_free_bytes/1073741824:.0f}G')" 2>/dev/null || echo "?")
    fi

    disk_int=${disk_usage%.*}

    # Validate that disk_int is numeric before arithmetic comparison
    if ! [[ "$disk_int" =~ ^[0-9]+$ ]]; then
        log "yellow" "Disk: invalid usage value '$disk_usage'"
        return 0
    fi

    if (( disk_int < 80 )); then
        log "green" "Disk: ${disk_usage}% (${disk_used}/${disk_total}) | Free: ${disk_free}"
        return 0
    elif (( disk_int < 90 )); then
        log "yellow" "Disk: ${disk_usage}% (${disk_used}/${disk_total}) | Free: ${disk_free}"
        return 0
    else
        log "red" "Disk: ${disk_usage}% (${disk_used}/${disk_total}) | Free: ${disk_free}"
        return 1
    fi
}

run_healthcheck() {
    local errors=0

    echo "SERVICE STATUS"
    echo "================================"
    check_novnc || errors=$((errors + 1))
    check_ttyd || errors=$((errors + 1))
    check_vnc || errors=$((errors + 1))
    echo ""

    echo "USER & AUTHENTICATION"
    echo "================================"
    check_temp_user || errors=$((errors + 1))
    echo ""

    echo "SSL CERTIFICATE"
    echo "================================"
    check_ssl_cert || errors=$((errors + 1))
    echo ""

    echo "SYSTEM RESOURCES"
    echo "================================"
    check_memory || errors=$((errors + 1))
    check_cpu || errors=$((errors + 1))
    check_disk || errors=$((errors + 1))
    echo ""

    echo "HEALTH SUMMARY"
    echo "================================"
    if (( errors == 0 )); then
        log "green" "All health checks passed - System healthy"
        return 0
    else
        log "red" "Health checks failed with $errors error(s)"
        return 1
    fi
}

auto_restart_service() {
    local service="$1"
    local port="$2"
    local start_func="${3:-}"

    if [[ -z "$start_func" ]]; then
        log "red" "No start function specified for $service"
        return 1
    fi

    if ! check_port_available "$port"; then
        # Port is in use, service is running
        return 0
    fi

    log "yellow" "Attempting to restart $service..."

    if ! declare -f "$start_func" &>/dev/null; then
        log "red" "Start function '$start_func' is not defined for $service"
        return 1
    fi

    if "$start_func"; then
        log "green" "$service restarted successfully"
    else
        log "red" "Failed to restart $service"
    fi
}

auto_restart_all() {
    log "cyan" "Checking and restarting services..."
    auto_restart_service "noVNC" "$NOVNC_PORT" "start_novnc"
    auto_restart_service "ttyd" "$TTYD_PORT" "start_ttyd"
    auto_restart_service "VNC Server" "$VNC_PORT" "start_vnc_server"
}

start_health_monitor() {
    [[ "$HEALTHCHECK_ENABLED" != "true" ]] && return

    log "cyan" "CONTINUOUS HEALTH MONITORING STARTED"
    log "cyan" "   Interval: ${HEALTHCHECK_INTERVAL} seconds"
    log "cyan" "   Press CTRL+C to stop monitoring"
    echo ""

    while true; do
        echo ""
        echo "============================================================"
        echo "  HEALTH MONITOR - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
        echo ""

        run_healthcheck

        if [[ "$AUTO_RESTART" == "true" ]]; then
            echo ""
            log "yellow" "Checking for service restarts..."
            auto_restart_all
        fi

        echo ""
        echo "Next health check in ${HEALTHCHECK_INTERVAL} seconds..."
        echo ""

        sleep "$HEALTHCHECK_INTERVAL"
    done
}

# ============================================================================
# HEALTH WEB SERVER OVERRIDES
# ============================================================================

_gather_system_metrics() {
    local cpu_load memory_usage disk_usage process_count network_connections

    # CPU load via wmic
    cpu_load=$(wmic cpu get loadPercentage /Value 2>/dev/null | tr -d '\r' | grep LoadPercentage | cut -d= -f2 | head -1)
    [[ -z "$cpu_load" ]] && cpu_load="N/A"

    # Memory usage via wmic
    local mem_total mem_free
    local mem_info
    mem_info=$(wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value 2>/dev/null | tr -d '\r')
    mem_total=$(echo "$mem_info" | grep TotalVisibleMemorySize | cut -d= -f2)
    mem_free=$(echo "$mem_info" | grep FreePhysicalMemory | cut -d= -f2)
    if [[ -n "$mem_total" && -n "$mem_free" ]]; then
        local mem_used=$(( mem_total - mem_free ))
        memory_usage=$(( mem_used * 100 / mem_total ))
        memory_usage="${memory_usage}%"
    else
        memory_usage="N/A"
    fi

    # Disk usage via df (Git Bash) or wmic
    if df -h / &>/dev/null; then
        disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    else
        disk_usage=$(wmic logicaldisk where "DeviceID='C:'" get FreeSpace,Size /Value 2>/dev/null | tr -d '\r')
        local d_size d_free
        d_size=$(echo "$disk_usage" | grep Size | cut -d= -f2)
        d_free=$(echo "$disk_usage" | grep FreeSpace | cut -d= -f2)
        if [[ -n "$d_size" && -n "$d_free" ]]; then
            local d_used=$(( d_size - d_free ))
            disk_usage="$(( d_used * 100 / d_size ))%"
        else
            disk_usage="N/A"
        fi
    fi

    process_count=$(tasklist 2>/dev/null | wc -l | tr -d ' ')
    network_connections=$(netstat -an 2>/dev/null | grep -c ESTABLISHED)

    export CPU_LOAD="$cpu_load"
    export MEMORY_USAGE="$memory_usage"
    export DISK_USAGE="$disk_usage"
    export CPU_TEMP="N/A"
    export SYSTEM_LOAD="N/A"
    export PROCESS_COUNT="$process_count"
    export NETWORK_CONNECTIONS="$network_connections"
}

generate_health_html() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    local hostname kernel os
    hostname=$(hostname 2>/dev/null || echo "windows-host")
    kernel=$(uname -r 2>/dev/null || echo "N/A")
    os="Windows"

    # Run health checks and capture output
    local temp_file
    temp_file=$(mktemp) || return 1
    trap 'rm -f "$temp_file"' RETURN
    run_healthcheck > "$temp_file" 2>&1

    # Parse health check output into HTML
    _parse_health_status_to_html "$temp_file"

    # Gather system metrics
    _gather_system_metrics

    # Process template
    local template_file="$PROJECT_DIR/src/templates/health.html"
    if [[ -f "$template_file" ]]; then
        # Use envsubst if available, otherwise use Python
        if command -v envsubst &>/dev/null; then
            envsubst < "$template_file"
        else
            python3 -c "
import os, sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
for key, value in os.environ.items():
    content = content.replace('\$' + key, str(value))
    content = content.replace('\${' + key + '}', str(value))
print(content)
" "$template_file"
        fi
    else
        # Fallback: generate a simple HTML page
        cat <<EOF
<!DOCTYPE html>
<html>
<head><title>Health Status - $hostname</title></head>
<body>
<h1>Health Status</h1>
<p>Host: $hostname | OS: $os | Kernel: $kernel</p>
<p>Timestamp: $timestamp</p>
<h2>System Resources</h2>
<ul>
<li>CPU: ${CPU_LOAD:-N/A}</li>
<li>Memory: ${MEMORY_USAGE:-N/A}</li>
<li>Disk: ${DISK_USAGE:-N/A}</li>
<li>Processes: ${PROCESS_COUNT:-N/A}</li>
<li>Network Connections: ${NETWORK_CONNECTIONS:-N/A}</li>
</ul>
<h2>Service Status</h2>
<pre>$_SERVICE_STATUS_HTML</pre>
</body>
</html>
EOF
    fi
}

start_health_web_server() {
    [[ "$HEALTH_WEB_ENABLED" != "true" ]] && return

    log "yellow" "Starting health web server on port $HEALTH_WEB_PORT..."

    local script_path
    script_path="$PROJECT_DIR/src/lib/monitoring/health_web_server.py"

    if [[ ! -f "$script_path" ]]; then
        log "red" "Health web server script not found: $script_path"
        return 1
    fi

    # Start the Python health web server in the background
    HEALTH_WEB_PORT="$HEALTH_WEB_PORT" python3 "$script_path" &
    local py_pid=$!
    echo "$py_pid" > /tmp/health_web_server.pid 2>/dev/null || echo "$py_pid" > "$PROJECT_DIR/data/health_web_server.pid" 2>/dev/null

    sleep 2
    if check_port_available "$HEALTH_WEB_PORT"; then
        log "red" "Health web server failed to start on port $HEALTH_WEB_PORT"
        return 1
    fi

    log "green" "Health web server started on port $HEALTH_WEB_PORT (PID: $py_pid)"
}

stop_health_web_server() {
    [[ "$HEALTH_WEB_ENABLED" != "true" ]] && return

    log "yellow" "Stopping health web server..."

    local pid_file="/tmp/health_web_server.pid"
    [[ ! -f "$pid_file" ]] && pid_file="$PROJECT_DIR/data/health_web_server.pid"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null | tr -d '\r')
        if [[ -n "$pid" ]]; then
            taskkill /PID "$pid" /T /F 2>/dev/null || kill "$pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
    fi

    # Also kill any python process running health_web_server.py
    pkill -f "health_web_server.py" 2>/dev/null || true

    log "green" "Health web server stopped."
}

check_health_web_server() {
    if [[ -f "/tmp/health_web_server.pid" ]] || [[ -f "$PROJECT_DIR/data/health_web_server.pid" ]]; then
        local pid_file="/tmp/health_web_server.pid"
        [[ ! -f "$pid_file" ]] && pid_file="$PROJECT_DIR/data/health_web_server.pid"
        local pid
        pid=$(cat "$pid_file" 2>/dev/null | tr -d '\r')
        if [[ -n "$pid" ]] && tasklist /FI "PID eq $pid" /NH 2>/dev/null | grep -q "$pid"; then
            log "green" "Health web server is running (PID: $pid)"
            return 0
        else
            log "yellow" "Health web server PID file exists but process not running"
            rm -f "$pid_file"
            return 1
        fi
    else
        log "blue" "Health web server is not running"
        return 1
    fi
}

# ============================================================================
# SSL EXTRAS OVERRIDES
# ============================================================================

check_ssl_expiry() {
    if [[ ! -f "$SSL_CERT" ]]; then
        return 1
    fi

    local check_end_seconds=$((SSL_RENEW_DAYS * 86400))

    if openssl x509 -checkend "$check_end_seconds" -noout -in "$SSL_CERT" 2>/dev/null; then
        local expire_date
        expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        log "green" "SSL certificate is valid (expires: $expire_date)"
        return 0
    else
        local expire_date
        expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        log "yellow" "SSL certificate expires soon or is expired (expires: $expire_date)"
        log "cyan" "Attempting certificate renewal..."
        return 1
    fi
}

copy_ssl_certificates() {
    if [[ -f "$DUCK_DIR/fullchain.pem" && -f "$DUCK_DIR/privkey.pem" ]]; then
        log "yellow" "Using existing SSL certificates from Let's Encrypt..."
        mkdir -p "$(dirname "$SSL_CERT")" 2>/dev/null || true
        cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT" 2>/dev/null || true
        cp "$DUCK_DIR/privkey.pem" "$SSL_KEY" 2>/dev/null || true
        log "blue" "SSL certificates copied to:"
        log "blue" "  Certificate: $SSL_CERT"
        log "blue" "  Private Key: $SSL_KEY"
        fix_ssl_permissions
        return 0
    fi
    return 1
}

setup_ssl() {
    [[ -z "$DUCK_DOMAIN" ]] && {
        log "yellow" "No domain provided. Running without SSL."
        export DISABLE_SSL=true
        return
    }

    # Accept localhost / 127.0.0.1 / ::1 for self-signed mode
    if [[ "$DUCK_DOMAIN" == "localhost" || "$DUCK_DOMAIN" == "127.0.0.1" || "$DUCK_DOMAIN" == "::1" ]]; then
        log "cyan" "Local domain detected ($DUCK_DOMAIN), generating self-signed certificate..."
        if generate_ssl_certificates; then
            export DISABLE_SSL=false
            log "green" "Self-signed SSL certificates configured successfully"
        else
            log "yellow" "Failed to generate self-signed certificate. Running without SSL."
            export DISABLE_SSL=true
        fi
        return
    fi

    if check_ssl_expiry; then
        log "cyan" "SSL certificate is valid, verifying permissions..."
        if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
            fix_ssl_permissions
        else
            log "yellow" "SSL certificate files not found, attempting to copy from Let's Encrypt..."
            if copy_ssl_certificates; then
                export DISABLE_SSL=false
                log "green" "SSL certificates copied and permissions fixed"
            else
                log "yellow" "No valid SSL certificates found. Running without SSL."
                export DISABLE_SSL=true
                return
            fi
        fi
        export DISABLE_SSL=false
        return
    fi

    if generate_ssl_certificates; then
        mkdir -p "$(dirname "$SSL_CERT")" 2>/dev/null || true
        if [[ -f "$DUCK_DIR/fullchain.pem" ]]; then
            cp "$DUCK_DIR/fullchain.pem" "$SSL_CERT" 2>/dev/null || true
            cp "$DUCK_DIR/privkey.pem" "$SSL_KEY" 2>/dev/null || true
        fi
        fix_ssl_permissions
        export DISABLE_SSL=false
        log "green" "SSL certificates configured successfully"
    elif copy_ssl_certificates; then
        export DISABLE_SSL=false
        log "green" "SSL certificates copied from existing installation"
    else
        log "yellow" "No valid SSL certificates found. Running without SSL."
        export DISABLE_SSL=true
    fi
}

# ============================================================================
# ERROR HANDLING OVERRIDES
# ============================================================================
# Most error handling functions are Bash-pure and work on both platforms.
# We override only the ones that use Linux-specific commands.

recover_nginx_management() {
    local exit_code="$1"
    log_info "Attempting nginx management recovery (Windows)" "RECOVERY"

    if command -v nginx &>/dev/null; then
        if nginx -t 2>/dev/null; then
            log_info "Nginx configuration is valid" "RECOVERY"
        else
            log_error "Nginx configuration has errors" "RECOVERY"
            return 1
        fi
    else
        log_warn "nginx binary not found on Windows" "RECOVERY"
    fi
    return 0
}

# retry_with_backoff, safe_execute, safe_cleanup, get_error_stats are
# Bash-pure and work on Windows without modification.

# ============================================================================
# SERVICE EXTRAS OVERRIDES
# ============================================================================

configure_novnc() {
    # On Windows, noVNC is typically cloned to a local directory
    local novnc_dir="$PROJECT_DIR/novnc"
    if [[ -d "$novnc_dir" ]] && [[ -f "$novnc_dir/vnc.html" ]] && [[ ! -f "$novnc_dir/index.html" ]]; then
        cp "$novnc_dir/vnc.html" "$novnc_dir/index.html" 2>/dev/null || true
    fi
}
