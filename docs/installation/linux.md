# 🚀 Quick Start Guide

Start your VNC Remote Secure setup in 5 minutes. This project provides web-based
remote access to your machine through VNC (desktop) and terminal interfaces.

## 📋 Prerequisites

**Hardware:**
- Raspberry Pi 3B+, 4, or 5 (or any Linux server)
- 1GB+ RAM (2GB+ recommended)
- 8GB+ free storage
- Internet connection

**Software:**
- Raspberry Pi OS, Debian 12+, or Ubuntu 22.04+
- Python 3.11+
- Sudo access
- Optional: Domain name for SSL

## ⚡ Quick Setup (5 minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure
```

### 2. Install Python Dependencies

```bash
pip install -e ".[dev]"
```

### 3. Set Password and Run

```bash
# Basic setup (HTTP only)
TTYD_PASSWD="your-strong-password" ./vnc-remote start

# Or with SSL (recommended)
TTYD_PASSWD="your-strong-password" DUCK_DOMAIN=your-domain.duckdns.org EMAIL=your-email@your-domain.duckdns.org ./vnc-remote start
```

`vnc-remote start` starts all configured services (VNC, noVNC, terminal,
health, landing, and optional nginx). It does **not** install system
dependencies — run `./vnc-remote install` first to install apt packages,
nginx, SSL certificates, and systemd units.

## 🌐 Access Your Services

Once running, access your services:

### Without SSL (HTTP)
- **Landing portal:** `http://your-server:8000/` — links to every service

### With SSL (HTTPS, nginx)
- **Landing portal:** `https://your-domain.duckdns.org/`
- **VNC Desktop (noVNC):** `https://your-domain.duckdns.org/vnc/`
- **Web Terminal:** `https://your-domain.duckdns.org/terminal/`

> Backend services (noVNC :6080, terminal :5000, health :8080) bind to
> `127.0.0.1` by default — they are reached through the portal or nginx,
> never directly from the network. The landing portal itself enforces
> authentication (`LANDING_PASSWORD`).

## 🔐 First Time Setup

### 1. Set Passwords
Edit `.env` file (copy from `.env.example`):
```bash
cp .env.example .env
# Set for production; if empty, strong passwords are auto-generated
# and stored (owner-only) in <run_dir>/generated_credentials.env —
# e.g. /run/vnc-remote-secure/generated_credentials.env for a
# systemd deployment.
TTYD_PASSWD="your-strong-password"
VNC_PASSWORD="your-strong-password"

# Optional (for SSL)
DUCK_DOMAIN=your-domain.duckdns.org
EMAIL=your-email@your-domain.duckdns.org
```

### 2. Enable Nginx (Recommended)
```bash
# Add to .env
NGINX_ENABLED=true
```

### 3. Start Services
```bash
./vnc-remote start
```

## 📱 Access from Anywhere

### From Your Computer
1. Open your web browser
2. Go to your VNC or Web Terminal URL
3. Enter your credentials

### From Mobile Device
1. Open mobile browser
2. Access the same URLs
3. Full mobile support included

## 🛠️ Common Quick Commands

```bash
# Install dependencies and configure
./vnc-remote install

# Start services
./vnc-remote start

# Stop services
./vnc-remote stop

# Restart services
./vnc-remote restart

# Check status
./vnc-remote status

# Diagnose issues
./vnc-remote doctor

# Run all tests
make test-all

# View logs (verbose mode)
./vnc-remote start --verbose
```

## 🔧 Quick Troubleshooting

### Port Already in Use
```bash
# Check what's using ports
sudo netstat -tlnp | grep -E ':(6080|5000|5901)'

# Restart services to free ports
./vnc-remote restart
```

### Permission Denied
```bash
# Make the CLI wrapper executable
chmod +x vnc-remote

# Run with proper permissions
sudo ./vnc-remote install
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
- [ ] System updated: `sudo apt update && sudo apt upgrade`
- [ ] Python 3.11+ installed
- [ ] Internet connection working
- [ ] Domain pointing to server (if using SSL)
- [ ] Firewall allows the public entry ports only: 80 and 443 when
      nginx is enabled (backend ports 6080/5000/5901 stay on loopback
      — opening them publicly bypasses the auth gateway)

After setup:
- [ ] Services are running: `./vnc-remote status`
- [ ] Backend ports listen on loopback: `netstat -tlnp | grep -E "127.0.0.1:(6080|5000|5901)"`
- [ ] Web interface loads in browser
- [ ] Login credentials work

## Next Steps

- **[Configuration](../architecture/configuration.md)** - All configuration options
- **[Security Model](../architecture/security-model.md)** - Security best practices
- **[Troubleshooting](../user-guide/troubleshooting.md)** - Common issues

## Pro Tips

1. **Use Strong Passwords** - Always use unique, strong passwords
2. **Enable SSL** - Use HTTPS for production environments
3. **Monitor Resources** - Check CPU/memory usage regularly
4. **Backup Configuration** - Save your `.env` file
5. **Test Thoroughly** - Run tests before production deployment

---

**Need help?** Check the [Troubleshooting](../user-guide/troubleshooting.md) guide.
