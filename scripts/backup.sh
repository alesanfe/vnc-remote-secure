#!/bin/bash
# ============================================================================
# BACKUP SCRIPT
# ============================================================================

set -e
set -o pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Backup configuration
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_${TIMESTAMP}.tar.gz"
DATA_DIR="$PROJECT_DIR/data"
CONFIG_FILE="$PROJECT_DIR/.env"

echo -e "${BLUE}🔄 Creating backup...${NC}"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Create backup of important files
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude='*.log' \
    --exclude='*.tmp' \
    --exclude='backups/' \
    -C "$PROJECT_DIR" \
    data/ssl/ \
    .env \
    config/ 2>/dev/null || {
    echo -e "${YELLOW}⚠️  Warning: Some files may not exist, continuing...${NC}"
}

# Create backup info
cat > "$BACKUP_DIR/backup_info_${TIMESTAMP}.txt" << EOF
Backup created: $(date)
Project directory: $PROJECT_DIR
Backup file: $BACKUP_FILE
Contents: SSL certificates, environment file, configuration templates
EOF

echo -e "${GREEN}✅ Backup completed successfully!${NC}"
echo -e "${BLUE}📁 Backup saved to: $BACKUP_DIR/$BACKUP_FILE${NC}"
echo -e "${BLUE}📋 Info file: $BACKUP_DIR/backup_info_${TIMESTAMP}.txt${NC}"

# Keep only last 5 backups
cd "$BACKUP_DIR"
ls -t backup_*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm
echo -e "${BLUE}🧹 Cleaned up old backups (keeping last 5)${NC}"
