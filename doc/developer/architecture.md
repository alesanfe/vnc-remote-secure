# System Architecture

Technical architecture and design of the Raspberry Pi VNC Remote Setup system.

## 🏗️ Overview

The system provides secure remote access to Raspberry Pi through web-based interfaces using a modular, service-oriented architecture.

## 📐 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        User Layer                           │
├─────────────────────────────────────────────────────────────┤
│  Web Browser (Desktop/Mobile)                              │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   VNC Desktop   │  │   Web Terminal  │                  │
│  │   (noVNC)       │  │   (ttyd)        │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTPS/HTTP
┌─────────────────────────────────────────────────────────────┐
│                     Gateway Layer                           │
├─────────────────────────────────────────────────────────────┤
│  Nginx Reverse Proxy                                        │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   SSL/TLS       │  │   Rate Limiting │                  │
│  │   Termination   │  │   & Security    │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Proxy
┌─────────────────────────────────────────────────────────────┐
│                    Service Layer                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │     noVNC       │  │     ttyd        │  │    VNC       │ │
│  │   :6080         │  │   :5000         │  │   :5901      │ │
│  │   Web Client    │  │   Web Terminal  │  │  Server      │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Local Access
┌─────────────────────────────────────────────────────────────┐
│                    System Layer                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Desktop Env   │  │   User Mgmt     │  │   Security   │ │
│  │   (remote user) │  │   (temp user)   │  │ (Fail2ban)   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Component Architecture

### Core Components

#### 1. Main Script (`src/rpi-vnc-remote.sh`)
**Purpose:** Orchestration and entry point
**Responsibilities:**
- Configuration validation
- Dependency installation
- Service orchestration
- Error handling and cleanup
- Lifecycle management

#### 2. Service Modules (`src/lib/services.sh`)
**Purpose:** Service management
**Services:**
- VNC Server (tigervncserver)
- noVNC Proxy (novnc_proxy)
- Terminal Server (ttyd)
- User management

#### 3. Nginx Module (`src/lib/nginx.sh`)
**Purpose:** Reverse proxy configuration
**Features:**
- SSL/TLS termination
- Rate limiting
- URL routing
- Security headers

#### 4. Security Modules
- **Fail2ban** (`src/lib/fail2ban.sh`) - Brute force protection
- **Port Knocking** (`src/lib/portknock.sh`) - Access control
- **SSL Management** (`src/lib/ssl.sh`) - Certificate handling

#### 5. Monitoring Module (`src/lib/healthcheck.sh`)
**Purpose:** System health monitoring
**Checks:**
- Service availability
- Resource usage (CPU, memory, disk)
- SSL certificate status
- Auto-restart functionality

## 📁 Module Structure

```
src/
├── rpi-vnc-remote.sh          # Main orchestration script
└── lib/                       # Modular components
    ├── config.sh              # Configuration management
    ├── utils.sh               # Utility functions
    ├── services.sh            # Service management
    ├── nginx.sh               # Nginx configuration
    ├── ssl.sh                 # SSL/TLS handling
    ├── user.sh                # User management
    ├── healthcheck.sh         # Health monitoring
    ├── fail2ban.sh            # Fail2ban integration
    ├── portknock.sh           # Port knocking
    ├── monitoring.sh          # Prometheus/Grafana
    ├── recording.sh           # Session recording
    ├── user_ui.sh             # Web interface
    ├── alerts.sh              # Notifications
    └── notifications.sh       # Notification handling
```

## 🔄 Data Flow

### 1. Initialization Flow
```
1. Script Start → Configuration Validation
2. Dependency Check → Install Missing
3. User Creation → Permission Setup
4. Service Start → Health Check
5. Nginx Config → SSL Setup
6. Final Health Check → Ready State
```

### 2. Request Flow (HTTPS)
```
Browser → Nginx (SSL) → Service (noVNC/ttyd) → Backend (VNC/Shell)
```

### 3. Authentication Flow
```
User Request → nginx → Service → Authentication → Access Granted/Denied
```

### 4. Error Handling Flow
```
Error Detection → Logging → Cleanup → Service Restart → Notification
```

## 🔐 Security Architecture

### Multi-Layer Security

#### Layer 1: Network Security
- **SSL/TLS Encryption** - All traffic encrypted
- **Rate Limiting** - DDoS protection
- **Port Knocking** - Hidden services
- **Fail2ban** - Brute force protection

#### Layer 2: Application Security
- **Input Sanitization** - Command injection prevention
- **User Isolation** - Temporary user sessions
- **Secure Defaults** - Safe out-of-the-box configuration
- **Permission Management** - Least privilege principle

#### Layer 3: System Security
- **Automatic Cleanup** - Resource cleanup on exit
- **Process Isolation** - Service separation
- **Log Monitoring** - Security event tracking
- **Certificate Management** - Auto-renewal and validation

### Security Controls

```bash
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=vnc_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=terminal_limit:10m rate=5r/s;

# SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;

# Security headers
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
```

## 🚀 Service Architecture

### Service Dependencies

```
rpi-vnc-remote.sh (main)
├── config.sh (configuration)
├── utils.sh (utilities)
├── user.sh (user management)
├── services.sh (core services)
│   ├── VNC Server
│   ├── noVNC Proxy
│   └── ttyd
├── nginx.sh (reverse proxy)
├── ssl.sh (certificates)
├── healthcheck.sh (monitoring)
└── Optional modules
    ├── fail2ban.sh
    ├── portknock.sh
    ├── monitoring.sh
    └── user_ui.sh
```

### Service Lifecycle

#### 1. Startup Sequence
```
1. Configuration Validation
2. Dependency Installation
3. User Creation
4. SSL Setup (if enabled)
5. Service Startup (VNC → noVNC → ttyd)
6. Nginx Configuration
7. Health Check Initialization
8. Monitoring Setup (if enabled)
```

#### 2. Runtime Management
```
Health Checks → Service Monitoring → Auto-restart → Notifications
```

#### 3. Shutdown Sequence
```
Signal Handling → Service Stop → User Cleanup → Resource Release
```

## 📊 Monitoring Architecture

### Health Check System

#### Component Monitoring
- **Service Availability** - Port checks, process monitoring
- **Resource Usage** - CPU, memory, disk utilization
- **SSL Status** - Certificate expiration monitoring
- **Network Status** - Connectivity and performance

#### Alerting System
- **Threshold Monitoring** - Resource usage alerts
- **Service Failure** - Automatic restart notifications
- **Security Events** - Failed login attempts, anomalies
- **System Events** - Certificate expiry, disk space

### Metrics Collection

```bash
# System metrics
check_memory()  # Memory usage monitoring
check_cpu()     # CPU usage monitoring  
check_disk()    # Disk usage monitoring

# Service metrics
check_novnc()   # noVNC service status
check_ttyd()    # ttyd service status
check_vnc()     # VNC server status

# Security metrics
check_ssl_cert() # Certificate status
```

## 🔧 Configuration Architecture

### Configuration Hierarchy

```
1. Environment Variables (.env)
2. Command Line Arguments
3. Default Values (built-in)
4. Runtime Detection (system-specific)
```

### Configuration Management

#### 1. Validation Layer
- **Required Variables** - Essential configuration
- **Type Validation** - Data type checking
- **Range Validation** - Value bounds checking
- **Dependency Validation** - Inter-variable relationships

#### 2. Loading Layer
- **Environment Files** - .env loading
- **Argument Parsing** - Command line options
- **Default Fallback** - Built-in defaults
- **Runtime Detection** - System capabilities

#### 3. Application Layer
- **Service Configuration** - Service-specific settings
- **Security Configuration** - Security parameters
- **Performance Tuning** - Optimization settings
- **Feature Flags** - Optional features

## 🐳 Container Architecture

### Docker Compose Design

```
Services:
├── nginx (reverse proxy)
├── novnc (web VNC client)
├── vnc (VNC server)
├── ttyd (web terminal)
└── Network (bridge)
```

### Container Orchestration

#### Development Environment
- **Local Testing** - Quick setup for development
- **Integration Testing** - End-to-end testing
- **Configuration Validation** - Setup verification

#### Production Considerations
- **Security Hardening** - Container security
- **Resource Limits** - Memory/CPU constraints
- **Networking** - Service isolation
- **Persistence** - Data management

## 🔌 Extension Architecture

### Plugin System Design

#### Module Interface
```bash
# Standard module structure
module_init()     # Initialize module
module_config()  # Configure module
module_start()    # Start module services
module_stop()     # Stop module services
module_cleanup()  # Cleanup resources
module_health()  # Health check
```

#### Extension Points
- **Authentication** - Custom auth methods
- **Monitoring** - Additional metrics
- **Notifications** - Custom alerting
- **Security** - Additional security layers

### Integration Patterns

#### 1. Service Integration
- **Health Checks** - Standard health interface
- **Configuration** - Unified config management
- **Logging** - Centralized logging
- **Error Handling** - Consistent error patterns

#### 2. External Integration
- **APIs** - REST/GraphQL interfaces
- **Webhooks** - Event notifications
- **Databases** - Data persistence
- **Cloud Services** - Cloud integration

## 📈 Performance Architecture

### Optimization Strategies

#### 1. Network Optimization
- **Connection Pooling** - Reuse connections
- **Compression** - Data compression
- **Caching** - Response caching
- **Load Balancing** - Traffic distribution

#### 2. Resource Optimization
- **Memory Management** - Efficient memory usage
- **CPU Optimization** - Process scheduling
- **Disk I/O** - Efficient storage
- **Network I/O** - Optimized networking

#### 3. Service Optimization
- **Process Isolation** - Service separation
- **Resource Limits** - Resource constraints
- **Monitoring** - Performance tracking
- **Auto-scaling** - Dynamic adjustment

## 🔮 Future Architecture

### Scalability Considerations

#### Horizontal Scaling
- **Service Clustering** - Multiple instances
- **Load Distribution** - Traffic balancing
- **State Management** - Distributed state
- **Data Replication** - Data synchronization

#### Vertical Scaling
- **Resource Allocation** - Dynamic resources
- **Performance Tuning** - Optimization
- **Hardware Upgrades** - Capacity planning
- **Monitoring** - Resource tracking

### Technology Evolution

#### Emerging Technologies
- **WebAssembly** - Client-side processing
- **WebRTC** - Real-time communication
- **Container Orchestration** - Kubernetes
- **Edge Computing** - Distributed processing

#### Architecture Evolution
- **Microservices** - Service decomposition
- **Event-Driven** - Async processing
- **API Gateway** - Unified interface
- **Service Mesh** - Service communication

---

**Next:** [Testing Guide](testing.md) for testing architecture and strategies
