# 🏥 Health API Endpoint

## 📋 Overview
The health endpoint provides real-time system status information through a web interface.

## 🔗 Endpoint Details

### URL
```
GET https://your-domain.com/health
```

### Authentication
- **Public endpoint** (when SSL is enabled)
- **No authentication required** for basic health checks
- **Rate limited** to prevent abuse

### Response Format
- **Content-Type**: `text/html`
- **Response**: Interactive HTML dashboard with auto-refresh

## Features

### Real-time Information
- **System Information**: Hostname, OS, Kernel, Uptime
- **Service Status**: noVNC, ttyd, VNC Server with PIDs and addresses
- **Resource Usage**: Memory, CPU, Disk utilization
- **SSL Certificate**: Expiry date and validation status
- **User Management**: Temporary user status

### Interactive Elements
- **Auto-refresh**: Every 15 seconds (toggleable)
- **Manual refresh**: Instant update button
- **Responsive design**: Mobile-friendly interface
- **Status indicators**: Color-coded health status

## Template Variables

The HTML template uses the following environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `HOSTNAME` | System hostname | `pi` |
| `OS` | Operating system | `Raspberry Pi OS` |
| `KERNEL` | Kernel version | `6.1.21-v8+` |
| `UPTIME` | System uptime | `up 2 hours, 30 minutes` |
| `TIMESTAMP` | Current timestamp | `2026-04-28 21:13:00` |
| `SERVICE_STATUS` | Generated HTML of service statuses | Dynamic content |

## Implementation Details

### Backend Components
- **Health Web Server**: Python HTTP server on port 8080
- **Template Engine**: `envsubst` for variable substitution
- **Health Checks**: Bash scripts for system monitoring
- **Configuration**: `src/templates/health.html`

### Nginx Configuration
```nginx
location /health {
    access_log off;
    proxy_pass http://127.0.0.1:8080/health_status;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Health Check Process
1. **Request received** at `/health`
2. **Nginx proxies** to health web server
3. **Template processed** with current system data
4. **HTML generated** and returned to client
5. **Auto-refresh** updates every 15 seconds

## Status Indicators

| Status | Color | Meaning |
|--------|-------|---------|
| ✅ OK | Green | Service running normally |
| ❌ Error | Red | Service failed or not running |
| ⚠️ Warning | Yellow | Service degraded or attention needed |

## Troubleshooting

### Common Issues

#### Health Page Not Loading
```bash
# Check health web server
ps aux | grep health_web_server

# Check port 8080
ss -tlnp | grep :8080

# Restart health web server
./rpi-vnc-remote.sh restart
```

#### Missing Information
```bash
# Run complete health check
./scripts/health-check.sh

# Check environment variables
cat .env | grep -E "(NOVNC_PORT|TTYD_PORT|VNC_PORT)"
```

#### SSL Certificate Issues
```bash
# Check certificate expiry
openssl x509 -enddate -noout -in data/ssl/fullchain.pem

# Test certificate validity
openssl x509 -checkend 86400 -noout -in data/ssl/fullchain.pem
```

### Debug Mode
Enable verbose logging for detailed diagnostics:

```bash
# Set verbose mode
export VERBOSE=true

# Run with debug
./rpi-vnc-remote.sh health-check
```

## Security Considerations

- **Rate limiting**: Configured in nginx (10r/s for VNC, 5r/s for terminal)
- **SSL required**: HTTPS-only access recommended
- **Access logs**: Disabled for health endpoint (privacy)
- **Information disclosure**: Only system status, no sensitive data exposed

## Integration

### Monitoring Systems
The endpoint can be integrated with external monitoring:

```bash
# Simple health check
curl -k https://your-domain.com/health | grep -q "✅ All systems healthy"

# JSON extraction (with custom parsing)
curl -k https://your-domain.com/health | grep -o "✅.*running"
```

### Automation Scripts
```bash
#!/bin/bash
# Automated health monitoring
HEALTH_URL="https://your-domain.com/health"
RESPONSE=$(curl -k -s "$HEALTH_URL")

if echo "$RESPONSE" | grep -q "✅ All systems healthy"; then
    echo "System healthy"
    exit 0
else
    echo "System issues detected"
    echo "$RESPONSE" | grep -E "(❌|⚠️)"
    exit 1
fi
```

## Customization

### Template Modification
Edit `src/templates/health.html` to customize:
- Visual design (CSS)
- Information displayed
- Refresh intervals
- Additional monitoring metrics

### Status Checks
Modify health check functions in `src/lib/monitoring/healthcheck.sh` to add:
- Custom service monitoring
- Additional system metrics
- Custom alert thresholds
- Integration with external APIs
