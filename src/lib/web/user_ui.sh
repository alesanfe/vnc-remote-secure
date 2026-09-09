#!/bin/bash
# shellcheck disable=SC2155,SC2034,SC2086
# ============================================================================
# USER MANAGEMENT UI MODULE
# ============================================================================
# Configuration is centralized in core/config.sh (single source of truth).

# Install Flask dependencies
install_flask_deps() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return

    log "yellow" "Installing Flask dependencies..."

    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip

    # Install pinned dependencies from requirements.txt
    if [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
        pip3 install --user -r "$PROJECT_DIR/requirements.txt" 2>/dev/null \
            || sudo pip3 install -r "$PROJECT_DIR/requirements.txt"
    else
        pip3 install --user flask 2>/dev/null || sudo pip3 install flask
    fi

    success "Flask dependencies installed."
}

# Create Flask user management UI
create_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return

    log "yellow" "Creating User Management UI..."

    local ui_dir="$PROJECT_DIR/user_ui"
    mkdir -p "$ui_dir/templates"

    # Copy Flask app from template
    cp "$SCRIPT_DIR/lib/web/user_ui_app.py" "$ui_dir/app.py"

    # Copy templates
    cp -r "$SCRIPT_DIR/lib/web/templates" "$ui_dir/"

    success "User Management UI created."
}

# Start User UI
start_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return

    log "yellow" "Starting User Management UI..."

    local ui_dir="$PROJECT_DIR/user_ui"
    (
        cd "$ui_dir" || return
        python3 app.py &
    )

    success "User Management UI started on port $USER_UI_PORT"
}

# Stop User UI
stop_user_ui() {
    [[ "$USER_UI_ENABLED" != "true" ]] && return

    log "yellow" "Stopping User Management UI..."

    pkill -f "python3.*app.py" 2>/dev/null || true

    success "User Management UI stopped."
}
