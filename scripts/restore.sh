#!/bin/bash
# ============================================================================
# RESTORE SCRIPT
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
BACKUP_DIR="$PROJECT_DIR/backups"

# Check if backup file is provided
if [[ $# -eq 0 ]]; then
    echo -e "${RED}❌ Error: Please provide a backup file${NC}"
    echo -e "${BLUE}Usage: $0 <backup_file.tar.gz>${NC}"
    echo -e "${BLUE}Available backups:${NC}"
    ls -la "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null || echo -e "${YELLOW}No backups found${NC}"
    exit 1
fi

BACKUP_FILE="$1"

# Check if backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    # Try to find it in backups directory
    if [[ -f "$BACKUP_DIR/$BACKUP_FILE" ]]; then
        BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE"
    else
        echo -e "${RED}❌ Error: Backup file not found: $BACKUP_FILE${NC}"
        echo -e "${BLUE}Available backups:${NC}"
        ls -la "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null || echo -e "${YELLOW}No backups found${NC}"
        exit 1
    fi
fi

echo -e "${BLUE}🔄 Restoring from backup: $BACKUP_FILE${NC}"

# Create restore info
RESTORE_INFO="$BACKUP_DIR/restore_$(date +%Y%m%d_%H%M%S).txt"

# Ask for confirmation
echo -e "${YELLOW}⚠️  This will overwrite current SSL certificates and .env file${NC}"
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}🚫 Restore cancelled${NC}"
    exit 0
fi

# Create backup of current state before restore
echo -e "${BLUE}📋 Creating backup of current state...${NC}"
"$SCRIPT_DIR/backup.sh"

# Restore from backup
echo -e "${BLUE}📂 Extracting backup...${NC}"
tar -xzf "$BACKUP_FILE" -C "$PROJECT_DIR" || {
    echo -e "${RED}❌ Error: Failed to extract backup file${NC}"
    exit 1
}

# Set proper permissions
if [[ -d "$PROJECT_DIR/data/ssl" ]]; then
    chmod 600 "$PROJECT_DIR/data/ssl"/*.pem 2>/dev/null || true
    echo -e "${GREEN}🔒 SSL certificates permissions set${NC}"
fi

# Create restore info
cat > "$RESTORE_INFO" << EOF
Restore completed: $(date)
Backup file: $BACKUP_FILE
Project directory: $PROJECT_DIR
Restored contents: SSL certificates, environment file, configuration templates
EOF

echo -e "${GREEN}✅ Restore completed successfully!${NC}"
echo -e "${BLUE}📋 Restore info: $RESTORE_INFO${NC}"
echo -e "${YELLOW}🔄 Please restart services to apply restored configuration${NC}"
