#!/bin/bash
# ============================================================================
# HEALTH CHECK SCRIPT
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

echo -e "${BLUE}🏥 Raspberry Pi VNC Remote - Complete Health Check${NC}"
echo -e "${BLUE}================================================${NC}"

# Check project structure
echo -e "\n${YELLOW}📁 Project Structure Check${NC}"
structure_ok=true

if [[ -f "$PROJECT_DIR/rpi-vnc-remote.sh" ]]; then
    echo -e "${GREEN}✅ Main script exists${NC}"
else
    echo -e "${RED}❌ Main script missing${NC}"
    structure_ok=false
fi

if [[ -d "$PROJECT_DIR/src/lib" ]]; then
    echo -e "${GREEN}✅ Library directory exists${NC}"
else
    echo -e "${RED}❌ Library directory missing${NC}"
    structure_ok=false
fi

if [[ -d "$PROJECT_DIR/data/ssl" ]]; then
    echo -e "${GREEN}✅ SSL directory exists${NC}"
else
    echo -e "${YELLOW}⚠️  SSL directory missing (will be created)${NC}"
fi

if [[ -d "$PROJECT_DIR/config" ]]; then
    echo -e "${GREEN}✅ Config directory exists${NC}"
else
    echo -e "${RED}❌ Config directory missing${NC}"
    structure_ok=false
fi

# Check SSL certificates
echo -e "\n${YELLOW}🔒 SSL Certificates Check${NC}"
ssl_ok=true

if [[ -f "$PROJECT_DIR/data/ssl/fullchain.pem" ]]; then
    if openssl x509 -checkend 86400 -noout -in "$PROJECT_DIR/data/ssl/fullchain.pem" 2>/dev/null; then
        echo -e "${GREEN}✅ SSL certificate valid (expires in >24h)${NC}"
    else
        echo -e "${YELLOW}⚠️  SSL certificate expires soon or is expired${NC}"
        ssl_ok=false
    fi
else
    echo -e "${YELLOW}⚠️  SSL certificate not found${NC}"
    ssl_ok=false
fi

if [[ -f "$PROJECT_DIR/data/ssl/privkey.pem" ]]; then
    echo -e "${GREEN}✅ SSL private key exists${NC}"
else
    echo -e "${YELLOW}⚠️  SSL private key not found${NC}"
    ssl_ok=false
fi

# Check environment file
echo -e "\n${YELLOW}🔧 Environment Configuration Check${NC}"
env_ok=true

if [[ -f "$PROJECT_DIR/.env" ]]; then
    echo -e "${GREEN}✅ Environment file exists${NC}"
    
    # Check for required variables
    required_vars=("DUCK_DOMAIN" "EMAIL" "NOVNC_PORT" "TTYD_PORT" "VNC_PORT")
    for var in "${required_vars[@]}"; do
        if grep -q "^${var}=" "$PROJECT_DIR/.env"; then
            echo -e "${GREEN}✅ $var is set${NC}"
        else
            echo -e "${YELLOW}⚠️  $var not found in .env${NC}"
        fi
    done
else
    echo -e "${YELLOW}⚠️  Environment file not found${NC}"
    env_ok=false
fi

# Check services
echo -e "\n${YELLOW}🚀 Services Status Check${NC}"
services_ok=true

# Check nginx
if command -v nginx &>/dev/null; then
    if sudo nginx -t 2>/dev/null; then
        echo -e "${GREEN}✅ Nginx configuration valid${NC}"
        if sudo systemctl is-active --quiet nginx; then
            echo -e "${GREEN}✅ Nginx running${NC}"
        else
            echo -e "${YELLOW}⚠️  Nginx not running${NC}"
            services_ok=false
        fi
    else
        echo -e "${RED}❌ Nginx configuration invalid${NC}"
        services_ok=false
    fi
else
    echo -e "${YELLOW}⚠️  Nginx not installed${NC}"
fi

# Check for running VNC processes
if pgrep -f "tigervncserver" >/dev/null; then
    echo -e "${GREEN}✅ VNC server processes running${NC}"
else
    echo -e "${YELLOW}⚠️  No VNC server processes found${NC}"
fi

if pgrep -f "websockify" >/dev/null; then
    echo -e "${GREEN}✅ noVNC proxy running${NC}"
else
    echo -e "${YELLOW}⚠️  noVNC proxy not found${NC}"
fi

if pgrep -f "ttyd" >/dev/null; then
    echo -e "${GREEN}✅ ttyd running${NC}"
else
    echo -e "${YELLOW}⚠️  ttyd not found${NC}"
fi

# Check ports
echo -e "\n${YELLOW}🌐 Port Check${NC}"
ports_ok=true

ports=("6080" "5000" "5901")
services=("noVNC" "ttyd" "VNC")

for i in "${!ports[@]}"; do
    port=${ports[$i]}
    service=${services[$i]}
    
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        echo -e "${GREEN}✅ $service port $port is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  $service port $port not listening${NC}"
        ports_ok=false
    fi
done

# Check health web server
echo -e "\n${YELLOW}🌐 Health Web Server Check${NC}"
if ss -tlnp 2>/dev/null | grep -q ":8080 "; then
    echo -e "${GREEN}✅ Health web server running on port 8080${NC}"
else
    echo -e "${YELLOW}⚠️  Health web server not running${NC}"
fi

# Summary
echo -e "\n${BLUE}📊 Health Check Summary${NC}"
echo -e "${BLUE}========================${NC}"

if [[ "$structure_ok" == true && "$ssl_ok" == true && "$env_ok" == true && "$services_ok" == true && "$ports_ok" == true ]]; then
    echo -e "${GREEN}🎉 All systems healthy!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some issues detected. Please review above.${NC}"
    
    if [[ "$ssl_ok" == false ]]; then
        echo -e "${BLUE}💡 Tip: Run SSL setup or certificate renewal${NC}"
    fi
    
    if [[ "$services_ok" == false ]]; then
        echo -e "${BLUE}💡 Tip: Check service logs and restart if needed${NC}"
    fi
    
    if [[ "$env_ok" == false ]]; then
        echo -e "${BLUE}💡 Tip: Copy .env.example to .env and configure${NC}"
    fi
    
    exit 1
fi
