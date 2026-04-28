#!/bin/bash
# ============================================================================
# CLEANUP SCRIPT
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

echo -e "${BLUE}🧹 Raspberry Pi VNC Remote - Cleanup Script${NC}"
echo -e "${BLUE}==========================================${NC}"

# Function to ask for confirmation
confirm_action() {
    local message="$1"
    read -p "$message (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Clean logs
echo -e "\n${YELLOW}📋 Log Cleanup${NC}"
if [[ -d "$PROJECT_DIR/data/logs" ]]; then
    log_size=$(du -sh "$PROJECT_DIR/data/logs" 2>/dev/null | cut -f1)
    echo -e "${BLUE}Current log directory size: $log_size${NC}"
    
    if confirm_action "Clean logs older than 7 days?"; then
        find "$PROJECT_DIR/data/logs" -name "*.log" -mtime +7 -delete 2>/dev/null || true
        echo -e "${GREEN}✅ Old logs cleaned${NC}"
    fi
    
    if confirm_action "Clean all logs?"; then
        rm -f "$PROJECT_DIR/data/logs"/*.log 2>/dev/null || true
        echo -e "${GREEN}✅ All logs cleaned${NC}"
    fi
else
    echo -e "${BLUE}📁 Log directory not found, creating...${NC}"
    mkdir -p "$PROJECT_DIR/data/logs"
fi

# Clean temporary files
echo -e "\n${YELLOW}🗂️  Temporary Files Cleanup${NC}"
temp_files=(
    "/tmp/health_status.html"
    "/tmp/health_web_server.pid"
    "/tmp/vnc_*"
    "/tmp/ttyd_*"
    "/tmp/novnc_*"
)

for pattern in "${temp_files[@]}"; do
    if ls $pattern 1>/dev/null 2>&1; then
        echo -e "${BLUE}Found temporary files: $pattern${NC}"
        rm -f $pattern 2>/dev/null || true
        echo -e "${GREEN}✅ Cleaned: $pattern${NC}"
    fi
done

# Clean old backups (keep last 3)
echo -e "\n${YELLOW}💾 Backup Cleanup${NC}"
BACKUP_DIR="$PROJECT_DIR/backups"
if [[ -d "$BACKUP_DIR" ]]; then
    backup_count=$(ls -1 "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null | wc -l)
    echo -e "${BLUE}Current backups: $backup_count${NC}"
    
    if [[ $backup_count -gt 3 ]]; then
        if confirm_action "Remove old backups (keep last 3)?"; then
            cd "$BACKUP_DIR"
            ls -t backup_*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm
            echo -e "${GREEN}✅ Old backups removed${NC}"
        fi
    fi
else
    echo -e "${BLUE}📁 Backup directory not found${NC}"
fi

# Clean Docker resources (optional)
echo -e "\n${YELLOW}🐳 Docker Cleanup${NC}"
if command -v docker &>/dev/null; then
    echo -e "${BLUE}Docker is installed${NC}"
    
    if confirm_action "Clean Docker unused resources?"; then
        echo -e "${BLUE}🔄 Cleaning Docker...${NC}"
        docker system prune -f 2>/dev/null || echo -e "${YELLOW}⚠️  Docker cleanup failed (may need sudo)${NC}"
        echo -e "${GREEN}✅ Docker cleanup completed${NC}"
    fi
else
    echo -e "${BLUE}🐳 Docker not installed${NC}"
fi

# Clean system package cache
echo -e "\n${YELLOW}📦 System Package Cache Cleanup${NC}"
if confirm_action "Clean system package cache?"; then
    echo -e "${BLUE}🔄 Cleaning package cache...${NC}"
    
    if command -v apt-get &>/dev/null; then
        sudo apt-get clean 2>/dev/null || echo -e "${YELLOW}⚠️  apt-get clean failed${NC}"
        sudo apt-get autoremove -y 2>/dev/null || echo -e "${YELLOW}⚠️  apt-get autoremove failed${NC}"
        echo -e "${GREEN}✅ APT cache cleaned${NC}"
    elif command -v yum &>/dev/null; then
        sudo yum clean all 2>/dev/null || echo -e "${YELLOW}⚠️  yum clean failed${NC}"
        echo -e "${GREEN}✅ YUM cache cleaned${NC}"
    else
        echo -e "${YELLOW}⚠️  No supported package manager found${NC}"
    fi
fi

# Check disk space after cleanup
echo -e "\n${YELLOW}💽 Disk Space After Cleanup${NC}"
df -h "$PROJECT_DIR" 2>/dev/null | {
    read header
    echo "$header" | while IFS= read -r line; do
        echo -e "${BLUE}$line${NC}"
    done
}

echo -e "\n${GREEN}✅ Cleanup completed successfully!${NC}"
echo -e "${BLUE}💡 Run './scripts/health-check.sh' to verify system health${NC}"
