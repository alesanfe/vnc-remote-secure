#!/bin/bash
# ============================================================================
# CLEANUP SCRIPT
# ============================================================================

set -e
set -o pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get project directory (scripts/maintenance is two levels below root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}🧹 VNC Remote Secure - Cleanup Script${NC}"
echo -e "${BLUE}==========================================${NC}"

# Shared helpers
source "$SCRIPT_DIR/common.sh"

# Resolve the canonical platform directories via the Python package -
# the runtime uses XDG/FHS paths (/var/log/vnc-remote-secure,
# /run/vnc-remote-secure), not repo-relative ./logs or ./run.
export PYTHONPATH="$PROJECT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
_resolve_dir() {
    python3 - "$1" <<'PYEOF' 2>/dev/null || true
import sys
from vnc_remote_secure.core import paths
print(getattr(paths, sys.argv[1])())
PYEOF
}
LOG_DIR_PATH="${LOG_DIR:-$(_resolve_dir get_log_dir)}"
RUN_DIR_PATH="$(_resolve_dir get_run_dir)"
LOG_DIR_PATH="${LOG_DIR_PATH:-$PROJECT_DIR/logs}"
RUN_DIR_PATH="${RUN_DIR_PATH:-$PROJECT_DIR/run}"

# Clean logs
echo -e "\n${YELLOW}📋 Log Cleanup${NC}"
if [[ -d "$LOG_DIR_PATH" ]]; then
    log_size=$(du -sh "$LOG_DIR_PATH" 2>/dev/null | cut -f1)
    echo -e "${BLUE}Current log directory size: $log_size${NC}"

    if confirm_action "Clean logs older than 7 days?"; then
        find "$LOG_DIR_PATH" -name "*.log" -mtime +7 -delete 2>/dev/null || true
        echo -e "${GREEN}✅ Old logs cleaned${NC}"
    fi

    if confirm_action "Clean all logs?"; then
        rm -f "$LOG_DIR_PATH"/*.log 2>/dev/null || true
        echo -e "${GREEN}✅ All logs cleaned${NC}"
    fi
else
    echo -e "${BLUE}📁 Log directory not found ($LOG_DIR_PATH)${NC}"
fi

# Clean runtime files (PID files live in the canonical run dir).
# Deleting the .pid file of a LIVE service orphans it: the service
# manager can no longer stop/restart it. Only remove PID files whose
# process is already dead.
echo -e "\n${YELLOW}🗂️  Temporary Files Cleanup${NC}"
if [[ -d "$RUN_DIR_PATH/pids" ]]; then
    shopt -s nullglob
    for pidfile in "$RUN_DIR_PATH"/pids/*.pid; do
        pid=$(cat "$pidfile" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo -e "${BLUE}Keeping live PID file: $pidfile (PID $pid)${NC}"
        else
            rm -f -- "$pidfile" 2>/dev/null || true
            echo -e "${GREEN}✅ Cleaned stale PID file: $pidfile${NC}"
        fi
    done
    shopt -u nullglob
fi

# Clean old backups (keep last 3)
echo -e "\n${YELLOW}💾 Backup Cleanup${NC}"
BACKUP_DIR="$PROJECT_DIR/backups"
if [[ -d "$BACKUP_DIR" ]]; then
    # shellcheck disable=SC2012  # controlled filenames; ls -t sorts by mtime
    backup_count=$(ls -1 "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null | wc -l)
    echo -e "${BLUE}Current backups: $backup_count${NC}"
    
    if [[ $backup_count -gt 3 ]]; then
        if confirm_action "Remove old backups (keep last 3)?"; then
            # Use a subshell to avoid changing the working directory
            # shellcheck disable=SC2012  # ls -t = mtime order, controlled names
            (cd "$BACKUP_DIR" && ls -t backup_*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm)
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
df -h "$PROJECT_DIR" 2>/dev/null | while IFS= read -r line; do
    echo -e "${BLUE}$line${NC}"
done

echo -e "\n${GREEN}✅ Cleanup completed successfully!${NC}"
echo -e "${BLUE}💡 Run './scripts/maintenance/health-check.sh' to verify system health${NC}"
