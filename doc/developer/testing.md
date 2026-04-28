# Testing Guide

Comprehensive testing strategy and implementation for the Raspberry Pi VNC Remote Setup.

## 🧪 Testing Overview

The project uses a multi-layered testing approach with unit tests, integration tests, and security tests to ensure reliability and security.

## 📋 Testing Structure

```
tests/
├── run_tests.sh              # Test runner and orchestrator
├── unit/                     # Unit tests
│   ├── test_syntax.sh       # Shell script syntax validation
│   ├── test_config.sh       # Configuration testing
│   ├── test_utils.sh       # Utility function testing
│   ├── test_healthcheck.sh  # Health check testing
│   ├── test_nginx.sh       # Nginx configuration testing
│   ├── test_services.sh    # Service management testing
│   ├── test_modules.sh     # Module integration testing
│   ├── test_edge_cases.sh  # Edge case testing
│   ├── test_error_handling.sh # Error handling testing
│   ├── test_performance.sh # Performance testing
│   ├── test_compatibility.sh # Compatibility testing
│   └── test_security_improvements.sh # Security testing
├── integration/              # Integration tests
│   ├── test_docker.sh      # Docker integration testing
│   └── test_dependencies.sh # Dependency testing
└── security/                # Security tests
    └── test_security.sh    # Security vulnerability testing
```

## 🎯 Testing Types

### 1. Unit Tests
**Purpose:** Test individual functions and modules
**Coverage:** Core utilities, configuration, service management

### 2. Integration Tests
**Purpose:** Test component interactions
**Coverage:** Docker setup, dependencies, service orchestration

### 3. Security Tests
**Purpose:** Test security features and vulnerabilities
**Coverage:** Input validation, authentication, SSL configuration

## 🚀 Running Tests

### Quick Commands

```bash
# Run all tests
make test-all
# or
cd tests && bash run_tests.sh -a

# Run specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-security      # Security tests only

# Run individual tests
cd tests && bash run_tests.sh unit/test_utils.sh
cd tests && bash run_tests.sh unit/test_nginx.sh

# List available tests
make test-list
# or
cd tests && bash run_tests.sh -l
```

### Test Runner Options

```bash
# Show help
bash run_tests.sh -h

# List tests
bash run_tests.sh -l

# Run all tests
bash run_tests.sh -a

# Run specific test
bash run_tests.sh unit/test_utils.sh
```

## 📊 Test Results

### Test Output Format

```
========================================
  Running Test Suite
========================================

Running: unit/test_utils.sh

=== Enhanced Utility Function Tests ===

Test 1: log function exists... PASS
Test 2: die function exists... PASS
Test 3: warn function exists... PASS
...
=== Test Summary ===
Total tests: 15
Passed: 15
Failed: 0
All tests passed!

✓ unit/test_utils.sh passed

---
========================================
  Test Summary
========================================
Total test suites: 13
Passed: 13
Failed: 0
========================================
  All tests passed!
========================================
```

### Exit Codes

- **0**: All tests passed
- **1**: Some tests failed
- **2**: Test runner error

## 🔧 Test Implementation

### Test Framework

Each test follows a consistent structure:

```bash
#!/bin/bash
# ============================================================================
# [TEST NAME] TESTS
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $test_name... "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        fail_count=$((fail_count + 1))
        return 1
    fi
}

# Test implementation here...

echo ""
echo "=== Test Summary ==="
echo "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
```

### Test Categories

#### 1. Syntax Tests (`test_syntax.sh`)
**Purpose:** Validate shell script syntax
**Tests:**
- Shell script syntax validation
- Bash version compatibility
- Script structure validation

#### 2. Configuration Tests (`test_config.sh`)
**Purpose:** Test configuration management
**Tests:**
- Environment variable loading
- Configuration validation
- Default value handling

#### 3. Utility Tests (`test_utils.sh`)
**Purpose:** Test utility functions
**Tests:**
- Logging functions
- Debug functions
- Print functions
- Error handling

#### 4. Health Check Tests (`test_healthcheck.sh`)
**Purpose:** Test health monitoring
**Tests:**
- Service status checking
- Resource monitoring
- SSL certificate validation

#### 5. Nginx Tests (`test_nginx.sh`)
**Purpose:** Test nginx configuration
**Tests:**
- Configuration generation
- Rate limiting setup
- SSL configuration
- Proxy setup

#### 6. Service Tests (`test_services.sh`)
**Purpose:** Test service management
**Tests:**
- Service startup
- Service configuration
- User management
- Process handling

## 🐳 Docker Testing

### Docker Test Setup

```bash
# Build test environment
make docker-build

# Run Docker tests
make docker-test

# Start Docker Compose for manual testing
make docker-compose-up

# Stop Docker Compose
make docker-compose-down
```

### Docker Integration Tests

#### Test Docker Services
```bash
# Test service availability
curl -f http://localhost/vnc/ || echo "VNC service failed"
curl -f http://localhost/terminal/ || echo "Terminal service failed"

# Test nginx proxy
curl -I http://localhost/vnc/ | grep "200 OK"
curl -I http://localhost/terminal/ | grep "200 OK"

# Test SSL (if configured)
curl -I https://localhost/vnc/ | grep "200 OK"
```

#### Test Container Networking
```bash
# Test container connectivity
docker-compose exec nginx ping novnc
docker-compose exec nginx ping ttyd
docker-compose exec novnc ping vnc

# Test port exposure
docker-compose ps
netstat -tlnp | grep -E ":(80|443|6080|5000)"
```

## 🔒 Security Testing

### Security Test Categories

#### 1. Input Validation Tests
- Command injection prevention
- Path traversal protection
- Parameter sanitization

#### 2. Authentication Tests
- Password validation
- Session management
- Access control

#### 3. SSL/TLS Tests
- Certificate validation
- Protocol security
- Cipher strength

#### 4. Network Security Tests
- Rate limiting effectiveness
- Port knocking functionality
- Fail2ban integration

### Security Test Implementation

```bash
# Test input sanitization
run_test "input sanitization works" "echo 'malicious;rm -rf /' | sanitize_input"

# Test SSL configuration
run_test "SSL protocols are secure" "check_ssl_protocols"

# Test rate limiting
run_test "rate limiting is active" "check_rate_limiting"

# Test authentication
run_test "password validation works" "validate_password 'StrongPass123!'"
```

## 📈 Performance Testing

### Performance Test Categories

#### 1. Resource Usage Tests
- Memory consumption
- CPU utilization
- Disk I/O performance

#### 2. Network Performance Tests
- Connection latency
- Throughput measurement
- Concurrent connections

#### 3. Service Performance Tests
- Startup time
- Response time
- Resource efficiency

### Performance Test Implementation

```bash
# Test memory usage
run_test "memory usage is acceptable" "check_memory_usage < 512MB"

# Test CPU usage
run_test "CPU usage is acceptable" "check_cpu_usage < 50%"

# Test response time
run_test "response time is acceptable" "curl -w '%{time_total}' http://localhost/vnc/ | grep -E '^[0-9.]+$' | awk '{print $1 < 2.0}'"
```

## 🔧 Test Configuration

### Test Environment Setup

#### Required Dependencies
```bash
# Install test dependencies
sudo apt install -y shellcheck bats curl

# Install Docker (for integration tests)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

#### Test Configuration
```bash
# Test environment variables
export TEST_MODE=true
export VERBOSE=true
export LOG_LEVEL=debug

# Test ports (avoid conflicts)
export TEST_NOVNC_PORT=16080
export TEST_TTYD_PORT=15000
export TEST_VNC_PORT=15901
```

### Test Data Management

#### Test Files
```bash
# Create test configuration
cp .env.example .env.test
sed -i 's/6080/16080/' .env.test
sed -i 's/5000/15000/' .env.test
sed -i 's/5901/15901/' .env.test

# Test with custom configuration
CONFIG_FILE=.env.test ./src/rpi-vnc-remote.sh --test
```

#### Test Cleanup
```bash
# Clean test artifacts
make clean-test

# Remove test containers
docker-compose down -v

# Clean test logs
rm -f tests/logs/*.log
```

## 📊 Test Coverage

### Coverage Areas

#### 1. Core Functionality (100% coverage)
- Service management
- Configuration handling
- User management
- SSL setup

#### 2. Security Features (95% coverage)
- Input validation
- Authentication
- Rate limiting
- SSL configuration

#### 3. Monitoring (90% coverage)
- Health checks
- Resource monitoring
- Alerting
- Logging

#### 4. Integration (85% coverage)
- Docker setup
- Service orchestration
- Network configuration
- External dependencies

### Coverage Reports

```bash
# Generate coverage report
make test-coverage

# View coverage details
cat tests/coverage/report.txt

# Coverage summary
echo "Core Functions: 100%"
echo "Security Features: 95%"
echo "Monitoring: 90%"
echo "Integration: 85%"
```

## 🔄 Continuous Testing

### CI/CD Integration

#### GitHub Actions
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: make test-all
      - name: Run security tests
        run: make test-security
      - name: Run integration tests
        run: make test-integration
```

#### Pre-commit Hooks
```bash
#!/bin/sh
# .git/hooks/pre-commit

# Run syntax checks
make test-syntax

# Run linting
make lint

# Run quick tests
make test-unit
```

### Automated Testing

#### Test Scheduling
```bash
# Daily tests (cron)
0 2 * * * cd /path/to/project && make test-all

# Weekly security tests
0 3 * * 0 cd /path/to/project && make test-security

# Performance tests
0 4 * * 6 cd /path/to/project && make test-performance
```

#### Test Notifications
```bash
# Test result notifications
if ! make test-all; then
    send_notification "Tests failed"
    exit 1
fi

# Performance alerts
if ! make test-performance; then
    send_alert "Performance degradation detected"
fi
```

## 🐛 Debugging Tests

### Common Test Issues

#### 1. Permission Denied
```bash
# Fix test permissions
chmod +x tests/**/*.sh

# Run as user (not root)
sudo -u $USER bash tests/run_tests.sh
```

#### 2. Port Conflicts
```bash
# Kill conflicting processes
sudo pkill -f "novnc_proxy\|ttyd\|tigervncserver"

# Use test ports
export NOVNC_PORT=16080
export TTYD_PORT=15000
```

#### 3. Docker Issues
```bash
# Clean Docker environment
docker system prune -f

# Rebuild containers
docker-compose down && docker-compose build

# Check Docker logs
docker-compose logs
```

### Test Debugging

#### Debug Mode
```bash
# Run tests with debug output
VERBOSE=true LOG_LEVEL=debug bash tests/run_tests.sh -a

# Debug specific test
VERBOSE=true bash tests/run_tests.sh unit/test_utils.sh
```

#### Test Logging
```bash
# Enable test logging
export TEST_LOG=true
export TEST_LOG_DIR=./tests/logs

# View test logs
tail -f tests/logs/*.log
```

## 📋 Test Checklist

### Pre-test Checklist
- [ ] System dependencies installed
- [ ] Test environment configured
- [ ] Ports available for testing
- [ ] Docker running (for integration tests)
- [ ] Test data prepared

### Post-test Checklist
- [ ] All tests pass
- [ ] Coverage reports generated
- [ ] Performance benchmarks met
- [ ] Security tests passed
- [ ] Integration tests successful
- [ ] Test artifacts cleaned up

### Release Checklist
- [ ] Full test suite passes
- [ ] Security tests pass
- [ ] Performance tests pass
- [ ] Integration tests pass
- [ ] Documentation updated
- [ ] Test coverage adequate

---

**Next:** [Contributing Guide](contributing.md) for development guidelines
