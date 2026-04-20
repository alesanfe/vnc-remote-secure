#!/bin/bash
set -e  # Stop script on error

# Configuration Variables
export NOVNC_PORT="6080"
export TTYD_PORT="5000"
export TTYD_USERNAME="alesanfe"
export TTYD_PASSWD="wellington"
export TTYD_UID=$(id -u "$TTYD_USERNAME")
export TTYD_GID=$(id -g "$TTYD_USERNAME")
export TEMP_USER="remote"

# Flag to check if environment is already set up
CLEAN=false

# Trap CTRL+C to perform cleanup
trap cleanup INT EXIT

# Function to print messages with color and emoji
print_message() {
    local message=$1
    local color=$2
    local emoji=$3

    case $color in
        red)    color_code="\033[0;31m" ;;
        green)  color_code="\033[0;32m" ;;
        yellow) color_code="\033[0;33m" ;;
        blue)   color_code="\033[0;34m" ;;
        purple) color_code="\033[0;35m" ;;
        cyan)   color_code="\033[0;36m" ;;
        white)  color_code="\033[0;37m" ;;
        *)      color_code="\033[0m" ;;  # Default to no color
    esac

    echo -e "${color_code}${emoji} ${message}\033[0m"
}

# Function to clean up environment before exiting
cleanup() {
    print_message "Cleaning up environment..." "blue" "🧹"
    close_port $NOVNC_PORT
    close_port $TTYD_PORT
    close_port 5901
    tigervncserver -kill :2 || true
    pkill -f 'tigervncserver' || true
    rm -f ttyd.armhf*
    
    if id "$TEMP_USER" &>/dev/null; then
        print_message "Removing temporary user $TEMP_USER..." "yellow" "🚨"
        sudo pkill -u "$TEMP_USER" || true  # Kill any processes running under $TEMP_USER
        sudo deluser --remove-home "$TEMP_USER" || true
    fi
    
    print_message "✅ Cleanup complete." "green" "✔️"
}

# Function to close a port if in use
close_port() {
    local PORT=$1
    local PID=$(lsof -t -i :$PORT 2>/dev/null)
    if [ ! -z "$PID" ]; then
        print_message "Stopping process on port $PORT (PID: $PID)..." "yellow" "🛑"
        sudo kill -9 $PID
    else
        print_message "Port $PORT is not in use." "green" "✔️"
    fi
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

        print_message ".Xauthority file missing for $TEMP_USER. Copying from $TTYD_USERNAME..." "yellow" "⚠️"
        sudo cp /home/$TTYD_USERNAME/.Xauthority /home/$TEMP_USER/.Xauthority
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.Xauthority

        print_message "VNC password file missing for $TEMP_USER. Copying from $TTYD_USERNAME..." "yellow" "⚠️"
        sudo mkdir -p /home/$TEMP_USER/.vnc
        sudo cp /home/$TTYD_USERNAME/.vnc/passwd /home/$TEMP_USER/.vnc/
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.vnc/passwd

        # Ensure the correct permissions for .vnc directory and passwd file
        sudo chmod 700 /home/$TEMP_USER/.vnc
        sudo chown $TEMP_USER:$TTYD_GID /home/$TEMP_USER/.vnc
        sudo chmod 600 /home/$TEMP_USER/.vnc/passwd

        # Optionally, list files to confirm
        sudo -u $TEMP_USER ls -al /home/$TEMP_USER/.vnc/

        print_message "Temporary user $TEMP_USER created with UID $NEW_UID and same permissions as $TTYD_USERNAME." "green" "✅"
    fi
}





# Function to start ttyd server
start_ttyd() {
    print_message "Starting ttyd..." "blue" "💬"
    sudo -su $TEMP_USER ttyd -c "$TTYD_USERNAME:$TTYD_PASSWD" -p "$TTYD_PORT" bash &
}

# Function to start TigerVNC server
start_vnc_server() {

    # Starting the VNC server
    print_message "Starting TigerVNC server for $TEMP_USER..." "blue" "💻"
    sudo -u $TEMP_USER tigervncserver :2 -geometry "1920x1080" -depth 24 -rfbport 5901 -SecurityTypes VncAuth -localhost no

    # Check if VNC server started successfully
    if [[ $? -eq 0 ]]; then
        print_message "TigerVNC server started successfully." "green" "✅"
    else
        print_message "Error: Failed to start TigerVNC server." "red" "❌"
    fi
}


# Function to start noVNC proxy
start_novnc() {
    print_message "Starting noVNC on port $NOVNC_PORT..." "blue" "💻"
    /usr/share/novnc/utils/novnc_proxy --vnc 127.0.0.1:5901 --listen "$NOVNC_PORT" &
    print_message "noVNC started successfully on port $NOVNC_PORT." "green" "✅"
}

# Function to stop existing services before setting up new ones
destroy() {
    close_port "$NOVNC_PORT"
    close_port "$TTYD_PORT"
    close_port 5901
    rm -f ttyd.armhf*
    pkill -f 'tigervncserver' || true
}

# Check if ttyd is installed
check_ttyd_installed() {
    if command -v ttyd &>/dev/null; then
        print_message "ttyd is already installed." "green" "✅"
    else
        print_message "ttyd is not installed. Installing..." "yellow" "⚙️"
        install_ttyd
    fi
}

# Set proper file and directory permissions
set_permissions() {
    print_message "Setting file and directory permissions..." "cyan" "🔐"
    sudo chown -R "$TTYD_USERNAME":"$TTYD_GID" /home/"$TTYD_USERNAME"/.Xauthority || true
    sudo chmod 644 /home/"$TTYD_USERNAME"/.Xauthority || true
    sudo chown -R "$TEMP_USER":"$(id -g "$TEMP_USER")" /home/"$TEMP_USER"/.Xauthority || true
    sudo chmod 644 /home/"$TEMP_USER"/.Xauthority || true
    print_message "✅ Permissions set." "green" "✅"
}

# Close existing VNC sessions
close_vnc_sessions() {
    print_message "Closing existing VNC sessions..." "yellow" "🛑"
    tigervncserver -kill :2 || true
}

# Start the environment setup
setup_environment() {
    print_message "Starting environment setup..." "blue" "🚀"
    
    check_ttyd_installed
    create_temp_user
    start_ttyd
    start_vnc_server
    start_novnc
    set_permissions
    print_message "✅ Environment setup complete." "green" "✔️"
}

# Main Execution
setup_environment

# Wait for all background processes
wait

























