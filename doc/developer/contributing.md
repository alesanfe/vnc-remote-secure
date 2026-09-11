# Contributing Guide

Thank you for your interest in contributing to Raspberry Pi VNC Remote! This guide will help you get started.

## Table of Contents
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Bug Reports](#bug-reports)
- [Feature Requests](#feature-requests)

## Development Setup

### Prerequisites
- Linux system (Raspberry Pi OS recommended)
- Bash shell
- Git
- Basic knowledge of shell scripting

### Clone Repository
```bash
git clone https://github.com/your-username/raspberrypinoVNC.git
cd raspberrypinoVNC
```

### Install Dependencies
```bash
# Install required packages
make install-deps

# Or manually
sudo apt update
sudo apt install -y nginx tigervnc-standalone-server novnc ttyd openssl
```

### Development Environment
```bash
# Create development environment file
cp .env.example .env.dev

# Edit for development
nano .env.dev
```

## Code Style

### Shell Script Guidelines

#### 1. Script Headers
All scripts must include proper headers:
```bash
#!/bin/bash
# shellcheck disable=SC2034,SC2155
set -e
set -o pipefail
# ============================================================================
# MODULE PURPOSE - Brief Description
# ============================================================================
```

#### 2. Function Naming
- Use snake_case for function names
- Be descriptive but concise
- Prefix with category when appropriate
```bash
check_ssl_expiry()        # Good
ssl_check()              # Acceptable
chkssl()                 # Bad - too short
```

#### 3. Variable Naming
- Use UPPER_CASE for global variables
- Use snake_case for local variables
- Export only when necessary
```bash
# Global configuration
export SSL_CERT="/path/to/cert"
export NGINX_ENABLED="true"

# Local variables
local cert_path="$SSL_CERT"
local nginx_status="active"
```

#### 4. Error Handling
- Always use `set -e` and `set -o pipefail`
- Check command return codes
- Provide meaningful error messages
```bash
install_package() {
    local package="$1"
    
    if ! sudo apt-get install -y "$package"; then
        log "red" "Failed to install $package" "❌"
        return 1
    fi
    
    log "green" "Successfully installed $package" "✅"
}
```

#### 5. Logging
- Use the centralized logging function
- Include emoji indicators
- Use appropriate log levels
```bash
log "green" "Service started successfully" "✅"
log "yellow" "Warning: High memory usage" "⚠️"
log "red" "Error: Service failed to start" "❌"
log "blue" "Debug: Checking configuration" "🔍"
```

### File Organization

#### Directory Structure
```
src/lib/
├── core/           # Essential functionality
├── security/       # Security components
├── monitoring/     # Health and monitoring
├── web/           # Web components
├── communication/  # Notifications
└── features/      # Optional features
```

#### Module Dependencies
- Source modules in dependency order
- Use absolute paths when possible
- Handle missing modules gracefully
```bash
# Load required modules
load_module "core/config.sh"
load_module "core/utils.sh"
load_module "security/ssl.sh"
```

### Configuration Management

#### Environment Variables
- Use descriptive names
- Provide sensible defaults
- Document in .env.example
```bash
# Port configuration
export NOVNC_PORT="${NOVNC_PORT:-6080}"
export TTYD_PORT="${TTYD_PORT:-5000}"
export VNC_PORT="${VNC_PORT:-5901}"
```

#### Template Files
- Use `${VARIABLE}` syntax
- Keep templates in appropriate directories
- Document variable usage
```bash
# nginx.conf template
server_name ${DUCK_DOMAIN:-localhost};
proxy_pass http://127.0.0.1:${NOVNC_PORT:-6080}/;
```

## Testing

### Test Structure
```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── security/       # Security tests
└── test_utils.sh   # Test utilities
```

### Running Tests
```bash
# Run all tests
make test

# Run specific test suites
make test-unit
make test-integration
make test-security

# Run with coverage
make test-coverage
```

### Writing Tests

#### Unit Tests
```bash
#!/bin/bash
# Test configuration loading

test_config_loading() {
    # Setup
    local test_env="/tmp/test_env"
    echo "TEST_VAR=test_value" > "$test_env"
    
    # Test
    source "$test_env"
    
    # Assert
    if [[ "$TEST_VAR" != "test_value" ]]; then
        echo "FAIL: Config loading test"
        return 1
    fi
    
    echo "PASS: Config loading test"
    rm -f "$test_env"
}
```

#### Integration Tests
```bash
#!/bin/bash
# Test service startup

test_service_startup() {
    # Setup
    ./rpi-vnc-remote.sh stop
    
    # Test
    ./rpi-vnc-remote.sh start
    
    # Assert
    sleep 5
    if ! pgrep -f "tigervncserver" >/dev/null; then
        echo "FAIL: VNC service not running"
        return 1
    fi
    
    echo "PASS: Service startup test"
    ./rpi-vnc-remote.sh stop
}
```

### Test Coverage
- Aim for >80% code coverage
- Test error conditions
- Test edge cases
- Test configuration variations

## Submitting Changes

### Branch Strategy
- `main`: Stable release branch
- `develop`: Development branch
- `feature/*`: Feature branches
- `bugfix/*`: Bug fix branches
- `hotfix/*`: Critical fixes

### Commit Messages
Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

Examples:
```
feat(nginx): Add health check endpoint
fix(ssl): Resolve certificate renewal issue
docs(api): Update health endpoint documentation
test(health): Add integration tests for health checks
```

### Pull Request Process

1. **Create Branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Make Changes**
```bash
# Write code
# Add tests
# Update documentation
```

3. **Run Tests**
```bash
make test
make lint
```

4. **Commit Changes**
```bash
git add .
git commit -m "feat(module): Add your feature"
```

5. **Push Branch**
```bash
git push origin feature/your-feature-name
```

6. **Create Pull Request**
- Use descriptive title
- Fill out PR template
- Link relevant issues
- Request review

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Added new tests

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes (or documented)
```

## Code Review Guidelines

### Review Checklist
- [ ] Code is readable and maintainable
- [ ] Tests are comprehensive
- [ ] Documentation is updated
- [ ] No security vulnerabilities
- [ ] Performance impact considered
- [ ] Error handling is robust
- [ ] Logging is appropriate

### Review Process
1. **Automated Checks**: CI/CD pipeline
2. **Peer Review**: At least one reviewer
3. **Security Review**: For sensitive changes
4. **Documentation Review**: For API changes

### Providing Feedback
- Be constructive and specific
- Explain reasoning for suggestions
- Offer solutions, not just problems
- Respect different coding styles

## Bug Reports

### Bug Report Template
```markdown
## Bug Description
Clear and concise description of the bug

## Environment
- OS: [e.g., Raspberry Pi OS 11]
- Architecture: [e.g., arm64]
- Version: [e.g., v1.2.3]

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Screenshots
If applicable, add screenshots

## Additional Context
Any other relevant information
```

### Debug Information
Include system information:
```bash
./scripts/health-check.sh > debug_info.txt
```

## Feature Requests

### Feature Request Template
```markdown
## Feature Description
Clear description of the feature

## Problem Statement
What problem does this solve?

## Proposed Solution
How should this be implemented?

## Alternatives Considered
What other approaches were considered?

## Additional Context
Any other relevant information
```

## Development Tools

### Linting
```bash
# Shell script linting
make lint

# ShellCheck
shellcheck src/**/*.sh

# Format scripts
make format
```

### Debugging
```bash
# Enable debug mode
export VERBOSE=true
./rpi-vnc-remote.sh <command>

# Check syntax
bash -n src/**/*.sh

# Trace execution
bash -x src/rpi-vnc-remote.sh
```

### Performance Testing
```bash
# Benchmark startup time
time ./rpi-vnc-remote.sh start

# Memory usage
ps aux | grep rpi-vnc

# Network performance
curl -k -w "@curl-format.txt" https://localhost/health
```

## Security Considerations

### Secure Coding Practices
- Validate all inputs
- Use absolute paths
- Avoid eval and similar constructs
- Check return codes
- Use least privilege principle

### Security Testing
```bash
# Run security tests
make test-security

# Check for common vulnerabilities
gosec src/

# SSL/TLS testing
sslscan https://your-domain.com
```

## Release Process

### Version Management
- Use semantic versioning (MAJOR.MINOR.PATCH)
- Update CHANGELOG.md
- Tag releases in Git

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version bumped
- [ ] Release tagged
- [ ] Assets uploaded

## Getting Help

### Resources
- [Documentation](../README.md)
- [API Reference](../api/)
- [Troubleshooting Guide](../guides/troubleshooting.md)

### Community
- GitHub Issues: Report bugs and request features
- GitHub Discussions: General questions and ideas
- Code Reviews: Contribute to development

### Contact
- Maintainer: [Your Name]
- Email: [your.email@example.com]
- Discord: [Server link]

Thank you for contributing to Raspberry Pi VNC Remote! 🚀
