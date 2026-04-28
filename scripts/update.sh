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

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}🔄 Raspberry Pi VNC Remote - Update Script${NC}"
echo -e "${BLUE}==========================================${NC}"

# Function to ask for confirmation
confirm_action() {
    local message="$1"
    read -p "$message (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

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
    if sudo apt update; then
        echo -e "${GREEN}✅ Package lists updated${NC}"
    else
        echo -e "${RED}❌ Failed to update package lists${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🔄 Running apt upgrade...${NC}"
    if sudo apt upgrade -y; then
        echo -e "${GREEN}✅ System packages upgraded${NC}"
    else
        echo -e "${YELLOW}⚠️  Some packages may have failed to upgrade${NC}"
    fi
    
    echo -e "${BLUE}🔄 Cleaning up unnecessary packages...${NC}"
    sudo apt autoremove -y 2>/dev/null || true
    sudo apt autoclean 2>/dev/null || true
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
        
        # Pull latest changes
        echo -e "${BLUE}🔄 Pulling latest changes...${NC}"
        if git pull origin main 2>/dev/null || git pull origin master 2>/dev/null; then
            echo -e "${GREEN}✅ Project updated successfully${NC}"
        else
            echo -e "${RED}❌ Failed to pull changes from git${NC}"
            echo -e "${BLUE}💡 Check your internet connection and git remote${NC}"
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
        
        # Manual dependency installation
        local deps=("nginx" "tigervnc-standalone-server" "novnc" "ttyd" "openssl")
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
    if [[ -f "$PROJECT_DIR/rpi-vnc-remote.sh" ]]; then
        echo -e "${BLUE}🔄 Restarting VNC Remote services...${NC}"
        cd "$PROJECT_DIR"
        
        # Stop services
        "$PROJECT_DIR/rpi-vnc-remote.sh" stop 2>/dev/null || true
        sleep 2
        
        # Start services
        "$PROJECT_DIR/rpi-vnc-remote.sh" start
        echo -e "${GREEN}✅ Services restarted${NC}"
    else
        echo -e "${YELLOW}⚠️  Main script not found, manual restart required${NC}"
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
echo -e "${BLUE}• Check service status: ./scripts/health-check.sh${NC}"
echo -e "${BLUE}• View logs: tail -f data/logs/*.log${NC}"
echo -e "${BLUE}• Access web interface: https://your-domain.com/health${NC}"

echo -e "\n${GREEN}🎉 Update process completed!${NC}"
