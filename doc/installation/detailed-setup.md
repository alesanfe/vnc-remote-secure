# 📋 Detailed Installation Guide

Complete installation instructions for the Raspberry Pi VNC Remote Setup project.

## 🔧 System Requirements

### Hardware
- **Raspberry Pi**: 3B+, 4, or 5 (4GB+ RAM recommended)
- **RAM**: 1GB minimum, 2GB+ recommended
- **Storage**: 8GB free space, 16GB+ recommended
- **Network**: Ethernet or WiFi connection

### Software
- **OS**: Raspberry Pi OS (Bullseye+), Ubuntu 20.04+, Debian 11+
- **bash**: Version 4.0+
- **sudo**: Required for package installation
- **curl**: For downloading dependencies
- **git**: Optional for repository cloning

### Optional
- **Domain Name**: For SSL certificates (DuckDNS, No-IP)
- **Email**: For Let's Encrypt notifications
- **Docker**: For containerized testing

## 🔧 Installation Methods

### Method 1: Git Clone (Recommended)

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure
chmod +x src/rpi-vnc-remote.sh
```

**Advantages:**
- Latest updates with `git pull`
- Full source code access
- Easy to modify and contribute
- Recommended for security updates

### Method 2: Download Archive

```bash
# Download and extract
wget https://github.com/alesanfe/vnc-remote-secure/archive/main.zip
unzip main.zip
cd vnc-remote-secure-main

# Make executable
chmod +x src/rpi-vnc-remote.sh
```

### Method 3: Direct Installation

```bash
# Install to system
curl -fsSL https://raw.githubusercontent.com/alesanfe/vnc-remote-secure/main/src/rpi-vnc-remote.sh -o /tmp/rpi-vnc-remote.sh
sudo mv /tmp/rpi-vnc-remote.sh /usr/local/bin/rpi-vnc-remote
sudo chmod +x /usr/local/bin/rpi-vnc-remote
```

## ⚙️ Configuration

### 1. Basic Configuration

Copy the example configuration:
```bash
cp .env.example .env
```

Edit `.env` with your preferred editor:
```bash
nano .env
```

### 2. Required Settings

```bash
# Password for terminal access
TTYD_PASSWD=your_secure_password

# Password for VNC access
VNC_PASSWORD=your_vnc_password

# Temporary user for remote access
TEMP_USER=remote
TEMP_USER_PASS=your_temp_user_password
```

### 3. SSL/TLS Configuration (Recommended)

```bash
# Domain for SSL certificate
DUCK_DOMAIN=your-domain.duckdns.org

# Email for certificate notifications
EMAIL=your-email@example.com

# Enable nginx reverse proxy
NGINX_ENABLED=true
```

### 4. Advanced Configuration

```bash
# Custom ports (optional)
NOVNC_PORT=6080
TTYD_PORT=5000
VNC_PORT=5901

# VNC display settings
VNC_DISPLAY=:2
VNC_GEOMETRY=1920x1080
VNC_DEPTH=24

# Logging
LOG_LEVEL=info
VERBOSE=false
SHOW_LOGS=true
```

## 🚀 Running the Setup

### Basic Setup (HTTP Only)

```bash
# Simple setup with required passwords
TTYD_PASSWD=your_password VNC_PASSWORD=your_vnc_password ./src/rpi-vnc-remote.sh
```

### SSL Setup (Recommended)

```bash
# Full setup with SSL and nginx
./src/rpi-vnc-remote.sh
```

### Custom Setup

```bash
# With custom configuration file
CONFIG_FILE=my-config.env ./src/rpi-vnc-remote.sh

# With debug logging
VERBOSE=true ./src/rpi-vnc-remote.sh

# With specific log level
LOG_LEVEL=debug ./src/rpi-vnc-remote.sh
```

## 🔍 Verification Steps

### 1. Check Service Status

```bash
# Check running processes
ps aux | grep -E "novnc|ttyd|vnc|nginx"

# Check port availability
netstat -tlnp | grep -E ":(6080|5000|5901|80|443)"

# Check service status
systemctl status nginx 2>/dev/null || echo "nginx not running as service"
```

### 2. Test Web Access

```bash
# Test local access
curl -I http://localhost:6080/
curl -I http://localhost:5000/

# Test SSL (if configured)
curl -I https://your-domain.duckdns.org/vnc/
```

### 3. Test Authentication

Open your web browser and navigate to:
- **HTTP**: `http://your-pi-ip:6080/` (VNC) or `http://your-pi-ip:5000/` (Terminal)
- **HTTPS**: `https://your-domain.duckdns.org/vnc/` (VNC) or `https://your-domain.duckdns.org/terminal/` (Terminal)

## 🛠️ Troubleshooting Installation

### Common Issues

#### Permission Denied
```bash
# Fix script permissions
chmod +x src/rpi-vnc-remote.sh

# Fix directory permissions
sudo chown -R $USER:$USER ./
```

#### Port Already in Use
```bash
# Find processes using ports
sudo lsof -i :6080
sudo lsof -i :5000
sudo lsof -i :5901

# Kill conflicting processes
sudo pkill -f "novnc_proxy"
sudo pkill -f "ttyd"
sudo pkill -f "tigervncserver"
```

#### SSL Certificate Issues
```bash
# Test domain resolution
nslookup your-domain.duckdns.org

# Test port 80 accessibility
telnet your-domain.duckdns.org 80

# Manual certificate generation
sudo certbot --nginx -d your-domain.duckdns.org
```

#### Dependencies Missing
```bash
# Install missing dependencies
sudo apt update
sudo apt install -y curl wget git bash

# Install VNC dependencies
sudo apt install -y tigervnc-standalone-server novnc

# Install terminal dependencies
sudo apt install -y ttyd

# Install nginx (if needed)
sudo apt install -y nginx
```

### Debug Mode

```bash
# Run with debug logging
VERBOSE=true LOG_LEVEL=debug ./src/rpi-vnc-remote.sh

# Check logs in real-time
tail -f /var/log/nginx/error.log &
tail -f /var/log/syslog | grep -E "vnc|ttyd|novnc" &
```

## 🔒 Security Considerations

### 1. Password Security
- Use strong, unique passwords
- Change default passwords immediately
- Consider using password managers

### 2. Network Security
- Use SSL/TLS in production
- Configure firewall rules
- Consider VPN access for additional security

### 3. System Security
- Keep system updated
- Use dedicated user for remote access
- Enable Fail2ban for brute force protection

### 4. SSL Best Practices
- Use valid domain names
- Set up automatic renewal
- Monitor certificate expiration

## 📦 Installation Options

### 1. System Installation
```bash
# Install to system PATH
make install

# Run from anywhere
rpi-vnc-remote
```

### 2. Docker Installation
```bash
# Build Docker image
make docker-build

# Run with Docker Compose
make docker-compose-up
```

### 3. Service Installation
```bash
# Create systemd service
sudo tee /etc/systemd/system/rpi-vnc-remote.service > /dev/null <<EOF
[Unit]
Description=Raspberry Pi VNC Remote Setup
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/vnc-remote-secure
ExecStart=/home/pi/vnc-remote-secure/src/rpi-vnc-remote.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable rpi-vnc-remote
sudo systemctl start rpi-vnc-remote
```

## 🔄 Updates and Maintenance

### Updating the Project
```bash
# Update repository
git pull origin main

# Reinstall dependencies
make clean
./src/rpi-vnc-remote.sh
```

### Backup Configuration
```bash
# Backup configuration
cp .env .env.backup
cp -r ssl/ ssl.backup/

# Backup entire setup
tar -czf vnc-remote-backup-$(date +%Y%m%d).tar.gz .env ssl/ logs/
```

### Maintenance Tasks
```bash
# Clean temporary files
make clean

# Renew SSL certificates
sudo certbot renew

# Check system resources
df -h
free -m
top
```

## 📚 Next Steps

After successful installation:

1. **[Configuration Guide](configuration.md)** - Detailed configuration options
2. **[User Guide](../user-guide/getting-started.md)** - How to use the system
3. **[Security Guide](../user-guide/security.md)** - Security best practices
4. **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

## 🆘 Getting Help

If you encounter issues:

1. Check the [FAQ](../reference/faq.md)
2. Review [Troubleshooting](troubleshooting.md)
3. Search existing [GitHub Issues](https://github.com/alesanfe/vnc-remote-secure/issues)
4. Create a new issue with detailed information

---

**Installation complete!** 🎉 Now proceed to the [User Guide](../user-guide/getting-started.md) to learn how to use your new remote access system.
