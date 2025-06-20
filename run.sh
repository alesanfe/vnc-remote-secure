#!/bin/bash
set -e  # Stop script on error

# ======================
# User Configuration
# ======================
export TTYD_USERNAME="remoteadmin"
export TTYD_PASSWD="changeme"
export TTYD_UID=$(id -u "$TTYD_USERNAME")
export TTYD_GID=$(id -g "$TTYD_USERNAME")
export TEMP_USER="remote"
export TEMP_USER_PASS=$TTYD_PASSWD
export EMAIL="youremail@example.com"

# ======================
# Network Configuration
# ======================
export NOVNC_PORT="6080"
export TTYD_PORT="5000"
export VNC_PORT=5901

# ======================
# SSL Configuration
# ======================
export SSL_DIR="./ssl"
export DUCK_DOMAIN="yourdomain.duckdns.org"
export DUCK_DIR="/etc/letsencrypt/live/$DUCK_DOMAIN"
export SSL_CERT="$SSL_DIR/fullchain.pem"
export SSL_KEY="$SSL_DIR/privkey.pem"
export SSL_RENEW_DAYS=30

# ======================
# VNC Server Configuration
# ======================
export VNC_DISPLAY=":2"
export VNC_GEOMETRY="1280x720"
export VNC_DEPTH=24

trap cleanup INT EXIT

# ========== Helper Functions ==========

print_message() {
    local message=$1
    local color=$2
    local emoji=$3
    case $color in
        red) color_code="\033[0;31m" ;;
        green) color_code="\033[0;32m" ;;
        yellow) color_code="\033[0;33m" ;;
        blue) color_code="\033[0;34m" ;;
        *) color_code="\033[0m" ;;
    esac
    echo -e "${color_code}${emoji} ${message}\033[0m"
}

close_port() {
    local PORT=$1
    local PID=$(lsof -t -i :$PORT 2>/dev/null)
    if [ ! -z "$PID" ]; then
        print_message "Stopping process on port $PORT (PID: $PID)..." "yellow" "🛑"
        sudo kill -9 $PID
    fi
}

cleanup() {
    print_message "Cleaning up environment..." "blue" "🧹"
    close_port $NOVNC_PORT
    close_port $TTYD_PORT
    close_port $VNC_PORT
    if pgrep -x "Xtigervnc" > /dev/null; then
        sudo -u $TEMP_USER tigervncserver -kill $VNC_DISPLAY || true
        sudo pkill -f 'tigervncserver' || true
    fi
    if id "$TEMP_USER" &>/dev/null; then
        sudo pkill -u "$TEMP_USER" || true
        sudo deluser --remove-home "$TEMP_USER" || true
    fi
    print_message "✅ Cleanup complete." "green" "✔️"
}

install_dependencies() {
    print_message "Installing required packages..." "yellow" "⚙️"
    sudo apt update && sudo apt install -y \
        wget iproute2 lsof tigervnc-standalone-server novnc \
        xfce4 xfce4-goodies x11-xserver-utils certbot \
        python3-certbot-dns-standalone
    print_message "Dependencies installed successfully." "green" "✅"
}

create_ssl() {
    if [[ -f "$SSL_CERT" ]]; then
        local expire_date
        expire_date=$(openssl x509 -enddate -noout -in "$SSL_CERT" | cut -d= -f2)
        local expire_sec=$(date --date="$expire_date" +%s)
        local now_sec=$(date +%s)
        local days_left=$(( (expire_sec - now_sec) / 86400 ))
        if (( days_left > SSL_RENEW_DAYS )); then
            print_message "SSL still valid for $days_left days." "green" "🔐"
            export DISABLE_SSL=false
            return
        fi
    fi

    print_message "Creating new SSL certificate..." "yellow" "🔒"
    sudo rm -rf "$SSL_DIR"
    mkdir -p "$SSL_DIR"

    if certbot_output=$(sudo certbot certonly --standalone --preferred-challenges http -d "$DUCK_DOMAIN" \
        --email "$EMAIL" --agree-tos --no-eff-email --non-interactive --quiet --rsa-key-size 4096 2>&1); then
        print_message "SSL certificate created." "green" "✅"
        export DISABLE_SSL=false
    else
        print_message "SSL generation failed." "red" "❌"
        export DISABLE_SSL=true
        return
    fi

    sudo cp "$DUCK_DIR"/fullchain.pem "$SSL_CERT"
    sudo cp "$DUCK_DIR"/privkey.pem "$SSL_KEY"
}

create_temp_user() {
    if ! id "$TEMP_USER" &>/dev/null; then
        print_message "Creating temporary user $TEMP_USER..." "cyan" "👤"
        NEW_UID=$(( $(getent passwd | cut -d: -f3 | sort -n | tail -n 1) + 1 ))
        sudo useradd -m -u "$NEW_UID" -g "$TTYD_GID" -s /bin/bash "$TEMP_USER"
        echo "$TEMP_USER:$TEMP_USER_PASS" | sudo chpasswd

        sudo mkdir -p /home/$TEMP_USER/.vnc
        sudo cp -r /home/$TTYD_USERNAME/.vnc/* /home/$TEMP_USER/.vnc/
        sudo chown -R $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.vnc
        sudo chmod -R 700 /home/$TEMP_USER/.vnc

        sudo cp /home/$TTYD_USERNAME/.Xauthority /home/$TEMP_USER/.Xauthority
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.Xauthority

        print_message "Temporary user $TEMP_USER created." "green" "✅"
    fi
}

start_vnc_server() {
    print_message "Starting VNC server..." "blue" "🖥️"
    sudo -u $TEMP_USER tigervncserver $VNC_DISPLAY -geometry "$VNC_GEOMETRY" -depth $VNC_DEPTH -rfbport $VNC_PORT -localhost no
}

start_ttyd() {
    print_message "Starting ttyd..." "blue" "💬"
    if [[ "$DISABLE_SSL" == true ]]; then
        sudo -u $TEMP_USER ttyd -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    else
        sudo -u $TEMP_USER ttyd -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    fi
}

start_novnc() {
    print_message "Starting noVNC..." "blue" "🖥️"
    if [[ "$DISABLE_SSL" == true ]]; then
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT --listen "$NOVNC_PORT"
    else
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT \
            --listen "$NOVNC_PORT" --cert "$SSL_CERT" --key "$SSL_KEY" --ssl-only
    fi
}

# ========== Main Execution ==========

install_dependencies
create_ssl
create_temp_user
start_vnc_server
start_ttyd
start_novnc
