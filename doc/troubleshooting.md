# Troubleshooting Guide

This guide covers common issues and their solutions for Raspberry Pi VNC Remote.

## Table of Contents
- [Installation Issues](#installation-issues)
- [Service Problems](#service-problems)
- [Network and Connectivity](#network-and-connectivity)
- [SSL Certificate Issues](#ssl-certificate-issues)
- [Performance Issues](#performance-issues)
- [User Management](#user-management)
- [Health Check Problems](#health-check-problems)

## Installation Issues

### Script Not Found
**Error**: `bash: rpi-vnc-remote.sh: No such file or directory`

**Solution**:
```bash
# Make sure you're in the project directory
cd /path/to/raspberrypinoVNC

# Make script executable
chmod +x rpi-vnc-remote.sh

# Run script
./rpi-vnc-remote.sh
```

### Permission Denied
**Error**: `Permission denied`

**Solution**:
```bash
# Fix permissions
chmod +x rpi-vnc-remote.sh

# If still fails, check file ownership
sudo chown $USER:$USER rpi-vnc-remote.sh
```

### Dependencies Missing
**Error**: Package installation failures

**Solution**:
```bash
# Update package lists
sudo apt update

# Fix broken packages
sudo apt --fix-broken install

# Install dependencies manually
sudo apt install -y nginx tigervnc-standalone-server novnc ttyd openssl
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
# Kill existing VNC processes
pkill -f tigervncserver

# Remove lock files
rm -f /tmp/.X11-unix/X*

# Restart VNC
./rpi-vnc-remote.sh restart

# If still fails, check display number
export DISPLAY=:1
./rpi-vnc-remote.sh start
```

### noVNC Proxy Not Working
**Symptoms**: Web interface loads but VNC connection fails

**Diagnosis**:
```bash
# Check noVNC process
ps aux | grep novnc

# Check noVNC port
ss -tlnp | grep :6080

# Check noVNC logs
journalctl -u novnc
```

**Solutions**:
```bash
# Restart noVNC
pkill -f novnc_proxy
./rpi-vnc-remote.sh restart

# Check firewall
sudo ufw status
sudo ufw allow 6080
```

### ttyd Terminal Not Accessible
**Symptoms**: Terminal page shows connection error

**Diagnosis**:
```bash
# Check ttyd process
ps aux | grep ttyd

# Check ttyd port
ss -tlnp | grep :5000

# Test ttyd manually
ttyd -p 5000 bash
```

**Solutions**:
```bash
# Restart ttyd
pkill -f ttyd
./rpi-vnc-remote.sh restart

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
cat src/config/nginx.conf

# Verify environment variables
env | grep -E "(NOVNC_PORT|TTYD_PORT|VNC_PORT)"

# Regenerate nginx config
sudo rm -f /etc/nginx/sites-enabled/rpi-vnc
./rpi-vnc-remote.sh restart
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

# Check iptables rules
sudo iptables -L

# Test port accessibility
telnet localhost 6080
```

**Solutions**:
```bash
# Allow required ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 6080/tcp
sudo ufw allow 5000/tcp
sudo ufw allow 5901/tcp

# Or disable firewall temporarily (testing only)
sudo ufw disable
```

## SSL Certificate Issues

### Certificate Expired
**Error**: SSL connection fails, certificate expired

**Diagnosis**:
```bash
# Check certificate expiry
openssl x509 -enddate -noout -in data/ssl/fullchain.pem

# Check certificate validity
openssl x509 -checkend 86400 -noout -in data/ssl/fullchain.pem
```

**Solutions**:
```bash
# Generate new certificate
./rpi-vnc-remote.sh ssl-setup

# Or use Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

### Certificate Path Issues
**Error**: SSL certificate not found

**Diagnosis**:
```bash
# Check certificate files
ls -la data/ssl/

# Check nginx configuration
grep ssl_cert /etc/nginx/sites-enabled/rpi-vnc
```

**Solutions**:
```bash
# Create SSL directory
mkdir -p data/ssl

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout data/ssl/privkey.pem \
    -out data/ssl/fullchain.pem

# Set correct permissions
chmod 600 data/ssl/*.pem
```

### Certificate Permissions
**Error**: Permission denied accessing SSL files

**Solution**:
```bash
# Set correct ownership
sudo chown $USER:$USER data/ssl/*

# Set correct permissions
chmod 600 data/ssl/privkey.pem
chmod 644 data/ssl/fullchain.pem
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
./rpi-vnc-remote.sh restart

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
./rpi-vnc-remote.sh restart

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
ping localhost

# Check nginx performance
sudo nginx -t && sudo systemctl reload nginx

# Check health web server
ps aux | grep health_web_server
```

**Solutions**:
```bash
# Restart web services
./rpi-vnc-remote.sh restart

# Clear browser cache
# Or test with curl
curl -k https://localhost/health
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
./rpi-vnc-remote.sh setup-user
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
# Check health web server
ps aux | grep health_web_server

# Check port 8080
ss -tlnp | grep :8080

# Check nginx configuration
grep -A 5 "location /health" /etc/nginx/sites-enabled/rpi-vnc
```

**Solutions**:
```bash
# Restart health web server
pkill -f health_web_server
./rpi-vnc-remote.sh restart

# Check nginx and restart if needed
sudo nginx -t && sudo systemctl restart nginx
```

### Missing Information
**Symptoms**: Health page shows incomplete data

**Diagnosis**:
```bash
# Run complete health check
./scripts/health-check.sh

# Check environment variables
env | grep -E "(NOVNC_PORT|TTYD_PORT|VNC_PORT)"

# Enable debug mode
export VERBOSE=true
./rpi-vnc-remote.sh health-check
```

**Solutions**:
```bash
# Reload environment
source .env

# Restart services
./rpi-vnc-remote.sh restart
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
curl -k https://localhost/health
```

## Getting Help

### Debug Mode
Enable verbose logging for detailed diagnostics:

```bash
export VERBOSE=true
./rpi-vnc-remote.sh <command>
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
tail -f data/logs/*.log
```

### Support Commands
Use these commands for system diagnostics:

```bash
# Complete health check
./scripts/health-check.sh

# System status
./rpi-vnc-remote.sh status

# Service restart
./rpi-vnc-remote.sh restart

# Configuration check
./rpi-vnc-remote.sh config-check
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

4. **Health Check Output**: `./scripts/health-check.sh`

5. **Steps to Reproduce**: What you did before the error

### Emergency Recovery
If the system is completely broken:

```bash
# Backup current state
./scripts/backup.sh

# Restore from last known good backup
./scripts/restore.sh backups/backup_YYYYMMDD_HHMMSS.tar.gz

# Or reset to defaults
./rpi-vnc-remote.sh uninstall
make install
```
