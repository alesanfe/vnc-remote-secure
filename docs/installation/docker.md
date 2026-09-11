# 🐳 Docker Configuration

## 📋 Docker Compose Files

This project contains two Docker Compose files for different purposes:

### 1. **docker-compose.integration.yml** (Integration Testing)
**Purpose**: Test the complete VNC Remote application stack

**Services**:
- **novnc**: noVNC web interface (port 6080)
- **vnc**: VNC server (port 5900)  
- **ttyd**: Terminal interface (port 5000)
- **nginx**: Reverse proxy (ports 80, 443)

**Usage**:
```bash
# Start integration testing environment
docker-compose -f docker-compose.integration.yml up -d

# Stop integration testing environment
docker-compose -f docker-compose.integration.yml down
```

### 2. **docker/docker-compose.yml** (Automated Testing)
**Purpose**: Run automated tests across different environments

**Services**:
- **test**: Main test environment (Ubuntu 22.04)
- **test-ubuntu**: Ubuntu-specific tests
- **test-debian**: Debian 11 tests
- **syntax-check**: Lightweight syntax validation

**Usage**:
```bash
# Run all tests
cd docker
docker-compose up

# Run specific test
cd docker
docker-compose run syntax-check
```

## 🔧 Configuration Details

### Integration Testing Environment
- Uses pre-built Docker images for quick setup
- Simulates production environment
- Tests service integration and connectivity
- Updated to use new project structure (`data/ssl`, `src/config/nginx.conf`)

### Automated Testing Environment  
- Builds custom Docker image with dependencies
- Tests across multiple Linux distributions
- Validates shell script syntax and functionality
- Suitable for CI/CD pipelines

## 📁 File Structure

```
raspberrypinoVNC/
├── docker-compose.integration.yml  # Integration testing
├── docker/
│   ├── Dockerfile                 # Test environment image
│   └── docker-compose.yml        # Automated testing
└── src/config/nginx.conf          # Nginx configuration
```

## 🚀 Quick Start

### For Integration Testing:
```bash
docker-compose -f docker-compose.integration.yml up -d
# Access:
# - noVNC: http://localhost:6080
# - Terminal: http://localhost:5000
# - Nginx: http://localhost (proxies to above)
```

### For Automated Testing:
```bash
cd docker
docker-compose run syntax-check
```

## 🐛 Troubleshooting

### Port Conflicts
If you encounter port conflicts, stop existing services:
```bash
# Stop integration tests
docker-compose -f docker-compose.integration.yml down

# Stop automated tests
cd docker && docker-compose down
```

### SSL Certificate Issues
The integration environment expects SSL certificates in `data/ssl/`:
```bash
# Generate test certificates
mkdir -p data/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout data/ssl/privkey.pem \
    -out data/ssl/fullchain.pem
```

### Volume Mount Issues
Ensure the project structure is correct:
```bash
# Should exist:
ls -la src/config/nginx.conf
ls -la data/ssl/
```

## 🔄 Development Workflow

1. **Local Development**: Use `./rpi-vnc-remote.sh` directly
2. **Integration Testing**: Use `docker-compose.integration.yml`
3. **Automated Testing**: Use `docker/docker-compose.yml`
4. **CI/CD**: Use automated testing environment

## 📝 Notes

- The integration environment uses external Docker images for speed
- The automated testing environment builds custom images for consistency
- Both environments are isolated and don't affect the host system
- SSL certificates are mounted read-only for security
