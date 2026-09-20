# Troubleshooting Guide

This guide covers common issues and their solutions for VNC Remote Secure.

## Table of Contents
- [Installation Issues](#installation-issues)
- [Service Problems](#service-problems)
- [Network and Connectivity](#network-and-connectivity)
- [SSL Certificate Issues](#ssl-certificate-issues)
- [Performance Issues](#performance-issues)
- [User Management](#user-management)
- [Health Check Problems](#health-check-problems)

## Installation Issues

### CLI Not Found
**Error**: `bash: vnc-remote: command not found`

**Solution**:
```bash
# Make sure you're in the project directory
cd /path/to/vnc-remote-secure

# Make the CLI wrapper executable
chmod +x vnc-remote

# Run setup/install
./vnc-remote install
```

### Permission Denied
**Error**: `Permission denied`

**Solution**:
```bash
# Fix permissions
chmod +x vnc-remote

# If still fails, check file ownership
sudo chown $USER:$USER vnc-remote
```

### Dependencies Missing
**Error**: Package installation failures

**Solution**:
```bash
# Update package lists
sudo apt update

# Fix broken packages
sudo apt --fix-broken install

# Install dependencies manually (the web terminal is the built-in
# Python/Tornado service — ttyd is only needed as an optional alternative)
sudo apt install -y nginx tigervnc-standalone-server novnc openssl
```

## Service Problems

### VNC Server Not Starting
**Symptoms**: VNC connection refused, health check shows VNC not running

**Diagnosis**:
```bash
# Check VNC processes
ps aux | grep tigervnc

# Check VNC logs
~/.vnc/*.log

# Check if port is listening
ss -tlnp | grep :5901
```

**Solutions**:
```bash
# Stop the managed VNC service by its recorded PID (the service
# manager refuses to kill PIDs it did not start — never pkill)
./vnc-remote stop

# Remove stale X11 lock files left by a crashed vncserver
rm -f /tmp/.X11-unix/X1

# Restart VNC (VNC_DISPLAY selects the display; the RFB port is
# 5900 + display number on Linux)
./vnc-remote start
```

### noVNC Proxy Not Working
**Symptoms**: Web interface loads but VNC connection fails

**Diagnosis**:
```bash
# Check noVNC process
ps aux | grep novnc

# Check noVNC port
ss -tlnp | grep :6080

# Check noVNC logs (services log to <log_dir>/novnc.log; the systemd
# unit is the unified vnc-remote.service)
journalctl -u vnc-remote
tail -f /var/log/vnc-remote-secure/novnc.log
```

**Solutions**:
```bash
# Restart noVNC
./vnc-remote restart

# Check firewall — remember: backend ports are loopback-only by
# design. Do NOT open 6080 publicly; access noVNC through nginx
# (port 443) so the auth gateway stays in front of it.
sudo ufw status
```

### Web Terminal Not Accessible
**Symptoms**: Web Terminal page shows connection error

**Diagnosis**:
```bash
# Check Web Terminal process
vnc-remote status

# Check Web Terminal port
ss -tlnp | grep :5000

# Test Web Terminal manually (Python Tornado backend, both platforms)
PYTHONPATH=src python -m vnc_remote_secure.services.terminal
```

**Solutions**:
```bash
# Restart Web Terminal service
./vnc-remote restart

# Check if port is in use
sudo lsof -i :5000
```

## Network and Connectivity

### Nginx Configuration Invalid
**Error**: `nginx: configuration file test failed`

**Diagnosis**:
```bash
# Test nginx configuration
sudo nginx -t

# Check nginx syntax
sudo nginx -T

# Check nginx logs
sudo journalctl -u nginx
```

**Solutions**:
```bash
# Check template file
cat src/vnc_remote_secure/config/nginx.conf

# Verify environment variables
env | grep -E "(NOVNC_PORT|TTYD_PORT|VNC_PORT)"

# Regenerate nginx config (the site file is named vnc-remote-secure)
sudo rm -f /etc/nginx/sites-enabled/vnc-remote-secure
./vnc-remote restart
```

### Port Conflicts
**Symptoms**: Services fail to start, port already in use

**Diagnosis**:
```bash
# Check all listening ports
ss -tlnp

# Check specific ports
ss -tlnp | grep -E ":(6080|5000|5901|80|443|8080)"

# Find process using port
sudo lsof -i :<port>
```

**Solutions**:
```bash
# Kill conflicting processes
sudo kill -9 <PID>

# Or change ports in .env
nano .env
# Edit NOVNC_PORT, TTYD_PORT, VNC_PORT
```

### Firewall Issues
**Symptoms**: Connection timeout, access denied

**Diagnosis**:
```bash
# Check firewall status
sudo ufw status

# Test port accessibility
telnet 127.0.0.1 6080
```

**Solutions**:
```bash
# Only the public entry point needs a rule — that is nginx (443/80).
# Backend ports (noVNC 6080, terminal 5000, VNC 5901) stay on
# loopback: opening them publicly bypasses the authentication
# gateway, so never add ufw rules for them.
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# If the deployment is LAN-only without nginx, restrict backend
# access to the LAN instead of opening it to the world, e.g.:
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp

# Or disable firewall temporarily (testing only)
sudo ufw disable
```

## SSL Certificate Issues

### Certificate Expired
**Error**: SSL connection fails, certificate expired

The canonical SSL directory is `get_ssl_dir()`:
`/var/lib/vnc-remote-secure/ssl` (root/systemd install),
`~/.local/share/vnc-remote-secure/ssl` (non-root Linux), or
`%ProgramData%\VncRemoteSecure\ssl` (Windows). Adjust the paths below
accordingly — the examples use the systemd path.

**Diagnosis**:
```bash
# Check certificate expiry
openssl x509 -enddate -noout -in /var/lib/vnc-remote-secure/ssl/fullchain.pem

# Check certificate validity
openssl x509 -checkend 86400 -noout -in /var/lib/vnc-remote-secure/ssl/fullchain.pem
```

**Solutions**:
```bash
# Generate new certificate
./vnc-remote install

# Or use Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

### Certificate Path Issues
**Error**: SSL certificate not found

**Diagnosis**:
```bash
# Check certificate files
ls -la /var/lib/vnc-remote-secure/ssl/

# Check nginx configuration
grep ssl_cert /etc/nginx/sites-enabled/vnc-remote-secure
```

**Solutions**:
```bash
# Regenerate into the canonical ssl directory (cert path overrides:
# SSL_CERT / SSL_KEY in .env)
./vnc-remote install

# Set correct permissions
chmod 600 /var/lib/vnc-remote-secure/ssl/*.pem
```

### Certificate Permissions
**Error**: Permission denied accessing SSL files

**Solution**:
```bash
# Set correct permissions (the service user must be able to read them;
# on a systemd install that is the vnc-remote user)
sudo chown vnc-remote:vnc-remote /var/lib/vnc-remote-secure/ssl/*
chmod 600 /var/lib/vnc-remote-secure/ssl/privkey.pem
chmod 644 /var/lib/vnc-remote-secure/ssl/fullchain.pem
```

## Performance Issues

### High CPU Usage
**Symptoms**: System slow, high CPU utilization

**Diagnosis**:
```bash
# Check CPU usage
top
htop

# Check process CPU usage
ps aux --sort=-%cpu | head -10

# Check system load
uptime
```

**Solutions**:
```bash
# Restart heavy processes
./vnc-remote restart

# Optimize VNC settings
# Edit .env and reduce resolution or color depth
```

### Memory Issues
**Symptoms**: Out of memory errors, swapping

**Diagnosis**:
```bash
# Check memory usage
free -h

# Check process memory
ps aux --sort=-%mem | head -10

# Check swap usage
swapon --show
```

**Solutions**:
```bash
# Clear system cache
sudo sync && sudo sysctl vm.drop_caches=3

# Restart services
./vnc-remote restart

# Add swap space if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Slow Web Interface
**Symptoms**: Health page loads slowly

**Diagnosis**:
```bash
# Check network latency
ping 127.0.0.1

# Check nginx performance
sudo nginx -t && sudo systemctl reload nginx

# Check health web server
ps aux | grep health_web_server
```

**Solutions**:
```bash
# Restart web services
./vnc-remote restart

# Clear browser cache
# Or test with curl
curl -k https://127.0.0.1/health
```

## User Management

### Temporary User Issues
**Symptoms**: Cannot create or delete remote user

**Diagnosis**:
```bash
# Check if user exists
id remote

# Check user processes
ps -u remote

# Check user home directory
ls -la /home/remote
```

**Solutions**:
```bash
# Kill user processes
sudo pkill -u remote

# Force user deletion
sudo userdel -rf remote

# Recreate user
./vnc-remote install
```

### SSH Agent Issues
**Symptoms**: User deletion blocked by ssh-agent

**Solution**:
```bash
# Kill ssh-agent processes
sudo pkill -f ssh-agent

# Find and kill specific agent
ps aux | grep ssh-agent
sudo kill -9 <PID>

# Then delete user
sudo userdel -rf remote
```

## Health Check Problems

### Health Page Not Loading
**Symptoms**: `/health` returns 404 or error

**Diagnosis**:
```bash
# Check health service status (managed by the service manager by PID —
# do not pkill by pattern)
vnc-remote status

# Check the health service log
tail -f /var/log/vnc-remote-secure/health.log

# Check port 8080 (8090 on Windows)
ss -tlnp | grep :8080

# Check nginx configuration
grep -A 5 "location /health" /etc/nginx/sites-enabled/vnc-remote-secure
```

**Solutions**:
```bash
# Restart via the service manager (stops/starts by recorded PID)
./vnc-remote restart

# Check nginx and restart if needed
sudo nginx -t && sudo systemctl restart nginx
```

### Missing Information
**Symptoms**: Health page shows incomplete data

**Diagnosis**:
```bash
# Run complete health check
./scripts/maintenance/health-check.sh

# Check environment variables
env | grep -E "(NOVNC_PORT|TTYD_PORT|VNC_PORT)"

# Enable debug mode
export VERBOSE=true
./scripts/maintenance/health-check.sh
```

**Solutions**:
```bash
# Reload environment
source .env

# Restart services
./vnc-remote restart
```

### Auto-refresh Not Working
**Symptoms**: Health page doesn't update automatically

**Solutions**:
```bash
# Check browser JavaScript console
# Look for JavaScript errors

# Test manual refresh
# Click refresh button or F5

# Check network connectivity
curl -k https://127.0.0.1/health
```

## Getting Help

### Debug Mode
Enable verbose logging for detailed diagnostics:

```bash
export VERBOSE=true
./vnc-remote <command>
```

### Log Files
Check these log files for detailed error information:

```bash
# System logs
sudo journalctl -u nginx
sudo journalctl -u systemd-logind

# VNC logs
ls ~/.vnc/*.log

# Application logs
tail -f logs/*.log
```

### Support Commands
Use these commands for system diagnostics:

```bash
# Complete health check
./scripts/maintenance/health-check.sh

# System status
./vnc-remote status

# Service restart
./vnc-remote restart

# Configuration check
./vnc-remote status
```

### Reporting Issues
When reporting issues, include:

1. **System Information**:
   ```bash
   uname -a
   lsb_release -a
   ```

2. **Error Messages**: Full error output

3. **Configuration**: Redacted `.env` file

4. **Health Check Output**: `./scripts/maintenance/health-check.sh`

5. **Steps to Reproduce**: What you did before the error

### Emergency Recovery
If the system is completely broken:

```bash
# Backup current state
vnc-remote backup

# Restore from last known good backup
vnc-remote restore backups/backup_YYYYMMDD_HHMMSS.tar.gz

# Or reset to defaults
make uninstall
make install
```
