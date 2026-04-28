# Raspberry Pi VNC Remote

Secure remote access to Raspberry Pi via browser using noVNC (desktop) and ttyd (terminal) with SSL/TLS support.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Script-blue.svg)](https://www.gnu.org/software/bash/)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-ARM64-green.svg)](https://www.raspberrypi.org/)

## Overview

Raspberry Pi VNC Remote provides secure, web-based remote access to your Raspberry Pi. It combines:

- **Desktop Access** - Full GUI via noVNC web interface
- **Terminal Access** - Command-line via ttyd web terminal
- **SSL/TLS Security** - Automatic HTTPS with Let's Encrypt
- **User Isolation** - Secure temporary user sessions
- **Health Monitoring** - Real-time system status dashboard

Perfect for remote administration, development, or accessing your Pi from anywhere with just a web browser.

## Quick Start

```bash
# Clonar el repositorio
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Configurar tus ajustes
cp .env.example .env
nano .env  # Configura dominio, email y contraseñas

# Ejecutar la instalación
./src/rpi-vnc-remote.sh setup
./src/rpi-vnc-remote.sh start
```

**Access your services:**
- **Desktop:** `https://your-domain.com/vnc/`
- **Terminal:** `https://your-domain.com/terminal/`
- **Health Status:** `https://your-domain.com/health`

## Key Features

### Core Features
- **Web-based Desktop** - Full Raspberry Pi desktop in browser
- **Web-based Terminal** - Secure shell access via web
- **SSL/TLS Encryption** - Automatic HTTPS certificates
- **Multi-architecture** - Raspberry Pi 3/4/5, Ubuntu, Debian
- **Auto-cleanup** - Removes temporary users on exit

### Security Features
- **SSL/TLS Support** - Let's Encrypt or self-signed certificates
- **User Isolation** - Dedicated temporary user per session
- **Rate Limiting** - Protection against brute force attacks
- **Port Knocking** - Additional security layer
- **Fail2Ban Integration** - Automatic IP blocking

### Management Features
- **Health Dashboard** - Real-time system monitoring
- **Automated Backups** - Configuration and data backup
- **System Maintenance** - Cleanup and update scripts
- **Docker Support** - Containerized testing environments

## Documentation

### Getting Started
- **[Quick Start](doc/installation/quick-start.md)** - Get running in 5 minutes
- **[Installation Guide](doc/installation/detailed-setup.md)** - Complete setup instructions
- **[Configuration](doc/installation/configuration.md)** - All configuration options

### User Guides
- **[User Guide](doc/user-guide/getting-started.md)** - How to use the system
- **[Security Guide](doc/user-guide/security.md)** - Security best practices
- **[Troubleshooting](doc/troubleshooting.md)** - Common issues and solutions

### Development & API
- **[API Documentation](doc/health-endpoint.md)** - Health endpoint API
- **[Contributing Guide](doc/developer/contributing.md)** - How to contribute
- **[Architecture](doc/developer/architecture.md)** - System design and structure

### Maintenance & Operations
- **[Docker Guide](doc/DOCKER.md)** - Docker testing environments
- **[Project Structure](doc/PROJECT_STRUCTURE.md)** - Project structure changes
- **[Maintenance Scripts](scripts/)** - Automated maintenance tools

## Project Structure

```
raspberrypinoVNC/
├── rpi-vnc-remote.sh          # Script principal
├── src/                       # Código fuente organizado
│   ├── lib/                   # Módulos por categorías
│   ├── config/                # Templates de configuración
│   └── templates/             # Templates HTML
├── data/                      # Runtime data
│   ├── ssl/                   # SSL certificates
│   └── logs/                  # System logs
├── scripts/                   # Maintenance scripts
│   ├── backup.sh              # Complete backup
│   ├── restore.sh             # Restore from backup
│   ├── health-check.sh        # System verification
│   ├── cleanup.sh             # System cleanup
│   └── update.sh              # System update
├── doc/                       # Complete documentation
└── tests/                     # Automated tests
```

## Maintenance Scripts

The project includes automated scripts for system maintenance:

```bash
# Complete system backup
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh backup_20260428_211300.tar.gz

# Complete system verification
./scripts/health-check.sh

# System cleanup
./scripts/cleanup.sh

# System update
./scripts/update.sh
```

## Docker Support

Para pruebas y desarrollo, el proyecto incluye configuración Docker:

```bash
# Testing de integración
docker-compose -f docker-compose.integration.yml up -d

# Tests automatizados
cd docker && docker-compose run syntax-check
```

## 🔧 Requisitos del Sistema

### Requisitos Mínimos
- **SO**: Raspberry Pi OS (Bullseye+), Ubuntu 20.04+, Debian 11+
- **Arquitectura**: armhf, arm64, o amd64
- **RAM**: 1GB+ (2GB+ recomendado para escritorio)
- **Almacenamiento**: 8GB+ de espacio libre
- **Red**: Conexión a internet para certificados SSL

### Requisitos Opcionales
- **Nombre de Dominio**: Para SSL/TLS (DuckDNS, No-IP, etc.)
- **Dirección Email**: Para notificaciones de Let's Encrypt
- **Docker**: Para pruebas contenerizadas

## 🚀 Comandos Principales

```bash
# Installation and configuration
./src/rpi-vnc-remote.sh setup

# Start services
./src/rpi-vnc-remote.sh start

# Stop services
./src/rpi-vnc-remote.sh stop

# Restart services
./src/rpi-vnc-remote.sh restart

# Check system status
./src/rpi-vnc-remote.sh status

# Health check completo
./scripts/health-check.sh
```

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor lee la [Guía de Contribución](doc/development/contributing.md) para detalles sobre cómo contribuir al proyecto.

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 🆘 Soporte

Si necesitas ayuda:

1. **Revisa la documentación** - La mayoría de las preguntas están respondidas
2. **Ejecuta health-check** - `./scripts/health-check.sh` para diagnosticar problemas
3. **Revisa troubleshooting** - [Guía de Solución de Problemas](doc/guides/troubleshooting.md)
4. **Abre un issue** - Para problemas específicos en GitHub

---

**🎉 ¡Accede a tu Raspberry Pi desde cualquier lugar con solo un navegador!**
