# 🚀 Quick Start Guide

Start your Raspberry Pi VNC Remote Setup in 5 minutes. This project provides web-based remote access to your Raspberry Pi through VNC (desktop) and terminal interfaces.

## 📋 Prerequisites

**Hardware:**
- Raspberry Pi 3B+, 4, or 5
- 1GB+ RAM (2GB+ recommended)
- 8GB+ free storage
- Internet connection

**Software:**
- Raspberry Pi OS, Ubuntu 20.04+, or Debian 11+
- Sudo access
- Optional: Domain name for SSL

## ⚡ Quick Setup (5 minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure
```

### 2. Set Password

```bash
export TTYD_PASSWD=your_secure_password
```

### 3. Run Setup

```bash
# Basic setup (HTTP only)
TTYD_PASSWD=your_secure_password ./src/rpi-vnc-remote.sh

# Or with SSL (recommended)
TTYD_PASSWD=your_secure_password DUCK_DOMAIN=your-domain.duckdns.org EMAIL=your-email@example.com ./src/rpi-vnc-remote.sh
```

The script installs VNC server, noVNC, ttyd, nginx, and starts all services.

## 🌐 Access Your Services

Once running, access your services:

### Without SSL (HTTP)
- **VNC Desktop:** `http://your-pi-ip:6080/`
- **Terminal:** `http://your-pi-ip:5000/`

### With SSL (HTTPS)
- **VNC Desktop:** `https://your-domain.duckdns.org/vnc/`
- **Terminal:** `https://your-domain.duckdns.org/terminal/`

## 🔐 First Time Setup

### 1. Set Passwords
Edit `.env` file:
```bash
# Required
TTYD_PASSWD=your_secure_password
VNC_PASSWORD=your_vnc_password

# Optional (for SSL)
DUCK_DOMAIN=your-domain.duckdns.org
EMAIL=your-email@example.com
```

### 2. Enable Nginx (Recommended)
```bash
# Add to .env
NGINX_ENABLED=true
```

### 3. Start Services
```bash
./src/rpi-vnc-remote.sh
```

## 📱 Access from Anywhere

### From Your Computer
1. Open your web browser
2. Go to your VNC or terminal URL
3. Enter your credentials

### From Mobile Device
1. Open mobile browser
2. Access the same URLs
3. Full mobile support included

## 🛠️ Common Quick Commands

```bash
# Install to system
make install

# Run all tests
make test-all

# View logs
VERBOSE=true ./src/rpi-vnc-remote.sh

# Stop services
Ctrl+C

# Clean up
make clean
```

## 🔧 Quick Troubleshooting

### Port Already in Use
```bash
# Check what's using ports
sudo netstat -tlnp | grep -E ':(6080|5000|5901)'

# Kill conflicting processes
sudo pkill -f "novnc_proxy\|ttyd\|tigervncserver"
```

### Permission Denied
```bash
# Make script executable
chmod +x src/rpi-vnc-remote.sh

# Run with proper permissions
sudo ./src/rpi-vnc-remote.sh
```

### SSL Certificate Issues
```bash
# Test domain resolution
nslookup your-domain.duckdns.org

# Check port 80/443 accessibility
curl -I http://your-domain.duckdns.org
```

## 📋 Quick Checklist

Before starting:
- [ ] Raspberry Pi updated: `sudo apt update && sudo apt upgrade`
- [ ] Internet connection working
- [ ] Domain pointing to Pi (if using SSL)
- [ ] Firewall allows ports 80, 443, 6080, 5000

After setup:
- [ ] Services are running: `ps aux | grep -E "novnc|ttyd|vnc"`
- [ ] Ports are accessible: `netstat -tlnp | grep -E ":(6080|5000|5901)"`
- [ ] Web interface loads in browser
- [ ] Login credentials work

## 🎯 Next Steps

- **[Detailed Installation](detailed-setup.md)** - Complete setup guide
- **[Configuration](configuration.md)** - All configuration options
- **[Security Guide](../user-guide/security.md)** - Security best practices
- **[Troubleshooting](troubleshooting.md)** - Common issues

## 💡 Pro Tips

1. **Use Strong Passwords** - Always use unique, strong passwords
2. **Enable SSL** - Use HTTPS for production environments
3. **Monitor Resources** - Check CPU/memory usage regularly
4. **Backup Configuration** - Save your `.env` file
5. **Test Thoroughly** - Run tests before production deployment

---

**Need help?** Check the [FAQ](../reference/faq.md) or [Troubleshooting](troubleshooting.md) guide.
