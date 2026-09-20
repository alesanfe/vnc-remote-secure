#!/bin/bash
# ============================================================================
# UPDATE SCRIPT
# ============================================================================

set -e
set -o pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get project directory (scripts/maintenance is two levels below root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}🔄 VNC Remote Secure - Update Script${NC}"
echo -e "${BLUE}==========================================${NC}"

# Shared helpers
source "$SCRIPT_DIR/common.sh"

# Resolve the canonical log directory via the Python package - the
# runtime uses XDG/FHS paths (/var/log/vnc-remote-secure), not
# repo-relative ./logs (same resolution as cleanup.sh).
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
LOG_DIR_PATH="${LOG_DIR:-$(python3 -c 'from vnc_remote_secure.core import paths; print(paths.get_log_dir())' 2>/dev/null || true)}"
LOG_DIR_PATH="${LOG_DIR_PATH:-$PROJECT_DIR/logs}"

# Check if we're in a git repository
if [[ ! -d "$PROJECT_DIR/.git" ]]; then
    echo -e "${YELLOW}⚠️  Not in a git repository${NC}"
    echo -e "${BLUE}💡 This script works best with git version control${NC}"
fi

# Create backup before update
echo -e "\n${YELLOW}📋 Creating backup before update...${NC}"
if [[ -f "$SCRIPT_DIR/backup.sh" ]]; then
    "$SCRIPT_DIR/backup.sh"
else
    echo -e "${YELLOW}⚠️  Backup script not found, continuing without backup${NC}"
fi

# Update system packages
echo -e "\n${YELLOW}📦 Updating system packages...${NC}"
if confirm_action "Update system packages?"; then
    echo -e "${BLUE}🔄 Running apt update...${NC}"
    if sudo apt-get update; then
        echo -e "${GREEN}✅ Package lists updated${NC}"
    else
        echo -e "${RED}❌ Failed to update package lists${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🔄 Running apt upgrade...${NC}"
    if sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq; then
        echo -e "${GREEN}✅ System packages upgraded${NC}"
    else
        echo -e "${YELLOW}⚠️  Some packages may have failed to upgrade${NC}"
    fi
    
    echo -e "${BLUE}🔄 Cleaning up unnecessary packages...${NC}"
    sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq 2>/dev/null || true
    sudo apt-get autoclean 2>/dev/null || true
    echo -e "${GREEN}✅ Package cleanup completed${NC}"
else
    echo -e "${BLUE}📋 Skipping system package update${NC}"
fi

# Update project from git
echo -e "\n${YELLOW}📥 Updating project from git...${NC}"
if [[ -d "$PROJECT_DIR/.git" ]]; then
    if confirm_action "Pull latest changes from git?"; then
        cd "$PROJECT_DIR"
        
        # Check for uncommitted changes
        if [[ -n $(git status --porcelain 2>/dev/null) ]]; then
            echo -e "${YELLOW}⚠️  You have uncommitted changes${NC}"
            if ! confirm_action "Continue anyway? (changes will be stashed)"; then
                echo -e "${BLUE}🚫 Update cancelled${NC}"
                exit 0
            fi
            git stash push -m "Auto-stash before update $(date)"
        fi
        
        # Pull latest changes (respect current branch)
        echo -e "${BLUE}🔄 Pulling latest changes...${NC}"
        current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
        if [[ -n "$current_branch" ]]; then
            if git pull origin "$current_branch" 2>/dev/null; then
                echo -e "${GREEN}✅ Project updated successfully (branch: $current_branch)${NC}"
            else
                echo -e "${RED}❌ Failed to pull changes from git${NC}"
                echo -e "${BLUE}💡 Check your internet connection and git remote${NC}"
                exit 1
            fi
        else
            echo -e "${RED}❌ Could not determine current branch${NC}"
            exit 1
        fi
        
        # Update submodules if any
        if git submodule status 2>/dev/null | grep -q .; then
            echo -e "${BLUE}🔄 Updating git submodules...${NC}"
            git submodule update --init --recursive
            echo -e "${GREEN}✅ Submodules updated${NC}"
        fi
    else
        echo -e "${BLUE}📋 Skipping git update${NC}"
    fi
else
    echo -e "${BLUE}📋 Not a git repository, skipping git update${NC}"
fi

# Update project dependencies
echo -e "\n${YELLOW}🔧 Updating project dependencies...${NC}"
if confirm_action "Update project dependencies and reinstall?"; then
    echo -e "${BLUE}🔄 Running make install...${NC}"
    cd "$PROJECT_DIR"
    
    if make install 2>/dev/null; then
        echo -e "${GREEN}✅ Project dependencies updated${NC}"
    else
        echo -e "${YELLOW}⚠️  Make install failed, trying manual installation...${NC}"
        
        # Manual dependency installation — mirrors the canonical
        # _SYSTEM_PACKAGES list in platform/linux/installer.py
        deps=("nginx" "fail2ban" "tigervnc-standalone-server" "tigervnc-common" "websockify" "openssl" "certbot" "python3-certbot-nginx")
        for dep in "${deps[@]}"; do
            echo -e "${BLUE}🔄 Installing $dep...${NC}"
            if sudo apt install -y "$dep"; then
                echo -e "${GREEN}✅ $dep installed${NC}"
            else
                echo -e "${YELLOW}⚠️  $dep may already be installed or failed${NC}"
            fi
        done
    fi
else
    echo -e "${BLUE}📋 Skipping dependency update${NC}"
fi

# Restart services
echo -e "\n${YELLOW}🚀 Restarting services...${NC}"
if confirm_action "Restart all services?"; then
    echo -e "${BLUE}🔄 Restarting VNC Remote services...${NC}"
    cd "$PROJECT_DIR"

    # Stop services via the canonical CLI (prefer repo wrapper over PATH)
    if [[ -x "$PROJECT_DIR/vnc-remote" ]]; then
        VNC_REMOTE="$PROJECT_DIR/vnc-remote"
    else
        VNC_REMOTE="vnc-remote"
    fi
    "$VNC_REMOTE" stop 2>/dev/null || true
    sleep 2

    # Start services via the canonical CLI
    if "$VNC_REMOTE" start; then
        echo -e "${GREEN}✅ Services restarted${NC}"
    else
        echo -e "${YELLOW}⚠️  Failed to restart services, manual restart required${NC}"
    fi
else
    echo -e "${BLUE}📋 Skipping service restart${NC}"
fi

# Run health check
echo -e "\n${YELLOW}🏥 Running health check...${NC}"
if [[ -f "$SCRIPT_DIR/health-check.sh" ]]; then
    echo -e "${BLUE}🔄 Checking system health...${NC}"
    "$SCRIPT_DIR/health-check.sh"
else
    echo -e "${YELLOW}⚠️  Health check script not found${NC}"
fi

# Show update summary
echo -e "\n${GREEN}✅ Update completed successfully!${NC}"
echo -e "${BLUE}📋 Update Summary:${NC}"
echo -e "${BLUE}• System packages updated${NC}"
echo -e "${BLUE}• Project source updated${NC}"
echo -e "${BLUE}• Dependencies refreshed${NC}"
echo -e "${BLUE}• Services restarted${NC}"
echo -e "${BLUE}• Health check completed${NC}"

echo -e "\n${BLUE}💡 Next steps:${NC}"
echo -e "${BLUE}• Check service status: ./scripts/maintenance/health-check.sh${NC}"
echo -e "${BLUE}• View logs: tail -f \"${LOG_DIR_PATH}\"/*.log${NC}"
echo -e "${BLUE}• Access web interface: https://your-domain.duckdns.org/health${NC}"

echo -e "\n${GREEN}🎉 Update process completed!${NC}"
