#!/bin/bash
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$SCRIPT_DIR/lib"

# Source all modules
source "$LIB_DIR/config.sh"
source "$LIB_DIR/utils.sh"
source "$LIB_DIR/ssl.sh"
source "$LIB_DIR/user.sh"
source "$LIB_DIR/services.sh"

# Handle command line arguments
handle_command "$1"

# Setup trap for cleanup
trap cleanup INT EXIT

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    print_banner
    
    [[ "$TTYD_PASSWD" == "changeme" ]] && {
        warn "Using default password. Please set TTYD_PASSWD environment variable."
    }
    
    install_dependencies
    setup_ssl
    create_temp_user
    inject_beef
    start_vnc_server
    start_ttyd
    start_novnc
    
    print_access_info
    success "Setup complete. Press CTRL+C to stop services."
    
    wait
}

main
