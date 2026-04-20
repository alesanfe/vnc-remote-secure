
## Raspberry Pi VNC Remote Setup

Secure remote access to Raspberry Pi via browser using noVNC (desktop) and ttyd (terminal) with optional SSL/TLS support.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/alesanfe/vnc-remote-secure.git
cd vnc-remote-secure

# Run the script (using wrapper from root)
chmod +x rpi-vnc-remote.sh
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org ./rpi-vnc-remote.sh

# Or run directly from src/
chmod +x src/rpi-vnc-remote.sh
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org ./src/rpi-vnc-remote.sh

# Or use Make
make run
```

## Using Makefile

The project includes a Makefile for common tasks:

```bash
make help              # Show all available commands
make install           # Install script to /usr/local/bin
make test              # Run all tests
make test-unit         # Run unit tests only
make docker-test       # Run tests in Docker
make clean             # Clean temporary files
make lint              # Run shellcheck linting
```

## Configuration

The script uses environment variables for configuration. See available options:

```bash
./src/rpi-vnc-remote.sh help
```

### Required Variables

- `TTYD_PASSWD` - Password for authentication (default: changeme)
- `DUCK_DOMAIN` - Domain for SSL certificate (optional, enables SSL)

### Common Variables

- `NOVNC_PORT` - Port for noVNC (default: 6080)
- `TTYD_PORT` - Port for ttyd (default: 5000)
- `VNC_PORT` - Port for VNC (default: 5901)
- `TEMP_USER` - Temporary user name (default: remote)
- `EMAIL` - Email for SSL certificate (default: user@example.com)

## Project Structure

```
raspberrypinoVNC/
├── src/
│   ├── rpi-vnc-remote.sh    # Main entry point
│   └── lib/
│       ├── config.sh        # Configuration variables
│       ├── utils.sh         # Logging, utilities, cleanup
│       ├── ssl.sh           # SSL/TLS management
│       ├── user.sh          # User management
│       └── services.sh      # Service management (ttyd, VNC, noVNC)
├── tests/
│   ├── unit/
│   │   ├── test_syntax.sh   # Syntax validation tests
│   │   ├── test_config.sh   # Configuration validation tests
│   │   ├── test_utils.sh    # Utility function tests
│   │   ├── test_modules.sh  # Module loading tests
│   │   ├── test_edge_cases.sh
│   │   └── test_error_handling.sh
│   ├── integration/
│   │   └── test_docker.sh  # Docker integration tests
│   ├── security/
│   │   └── test_security.sh
│   └── run_tests.sh         # Test runner
├── docker/
│   ├── Dockerfile           # Test environment
│   └── docker-compose.yml   # Orchestration
└── ssl/                    # SSL certificates (gitignored)
```

## Testing

The project includes unit tests that can be run locally without requiring another machine.

### Running All Tests

```bash
cd tests
chmod +x run_tests.sh
./run_tests.sh
```

### Running Individual Test Suites

```bash
# Syntax validation (requires shellcheck)
./tests/unit/test_syntax.sh

# Configuration validation
./tests/unit/test_config.sh

# Utility function tests
./tests/unit/test_utils.sh

# Module loading tests
./tests/unit/test_modules.sh

# Docker integration tests
./tests/integration/test_docker.sh

# Edge case tests
./tests/unit/test_edge_cases.sh

# Error handling tests
./tests/unit/test_error_handling.sh

# Security validation tests
./tests/security/test_security.sh
```

### Test Requirements

- **shellcheck**: Required for syntax validation tests (auto-installed if missing)
- **bash**: Version 4.0 or higher
- **sudo**: Some tests may require root privileges

### Test Coverage

- Syntax validation with shellcheck
- Configuration variable validation
- Utility function testing
- Module loading and dependency checks
- File structure validation
- Docker integration testing
- Edge case validation
- Error handling verification
- Security validation

## Docker Testing

The project includes Docker support for testing in isolated environments.

### Running Tests with Docker

```bash
# Build and run tests in Docker
cd docker
docker-compose run test

# Run specific test service
docker-compose run syntax-check

# Run on multiple distributions
docker-compose run test-ubuntu
docker-compose run test-debian
```

### Docker Compose Services

- **test**: Main test environment (Ubuntu 22.04)
- **test-ubuntu**: Ubuntu-specific tests
- **test-debian**: Debian 11 tests
- **syntax-check**: Lightweight syntax validation only

### CI/CD with GitHub Actions

The project includes automated testing via GitHub Actions that runs:
- Syntax checks
- Local unit tests
- Docker integration tests
- Multi-distro testing

Tests run automatically on push to `main` or `develop` branches and on pull requests.

## Features

- **noVNC**: HTML5 VNC client for desktop access via browser
- **ttyd**: Terminal sharing over web
- **SSL/TLS**: Secure connections with Let's Encrypt certificates
- **Auto-renewal**: SSL certificate renewal before expiration
- **Multi-arch**: Supports armhf, arm64, and amd64
- **Temporary user**: Isolated user for remote access
- **Cleanup**: Automatic cleanup on exit or with `./rpi-vnc-remote.sh stop`

## Usage Examples

### Basic (no SSL)
```bash
TTYD_PASSWD=mypassword ./rpi-vnc-remote.sh
```

### With SSL
```bash
TTYD_PASSWD=mypassword DUCK_DOMAIN=mydomain.duckdns.org EMAIL=my@email.com ./rpi-vnc-remote.sh
```

### Custom ports
```bash
TTYD_PASSWD=mypassword NOVNC_PORT=8080 TTYD_PORT=9000 ./rpi-vnc-remote.sh
```

### Stop services
```bash
./rpi-vnc-remote.sh stop
```

## Access Information

After running the script, access the services:

- **noVNC (Desktop)**: `http://localhost:6080` or `https://localhost:6080` (with SSL)
- **ttyd (Terminal)**: `http://localhost:5000` or `https://localhost:5000` (with SSL)

Use the credentials specified in `TTYD_USERNAME` and `TTYD_PASSWD`.

## Manual Configuration

For manual setup without the script, refer to the following sections:


# Explanation of the bash script

### Accessing rpi cmd over a browser using ttyd

ttyd is a simple command-line tool for sharing terminal over the web.

Download .arm version of ttyd binary from the following command
```
wget https://github.com/tsl0922/ttyd/releases/download/1.6.3/ttyd.armhf 
```

Copy the binary to /usr/local/bin/ttyd
```
sudo cp ttyd.armhf /usr/local/bin/ttyd
```

Changing permission
```
sudo chmod +x /usr/local/bin/ttyd
```

Running ttyd
```
sudo ttyd -c username:password -p {PORT_NUMBER} bash &
```

You can now access terminal by entering http://localhost:{PORT-NUMBER} on your browser.







## noVNC

noVNC is both a HTML VNC client JavaScript library and an application built on top of that library. noVNC runs well in any modern browser including mobile browsers (iOS and Android).

For more information you can check their official documentation here https://github.com/novnc/noVNC

#### Installing noVNC and TigerVNC server
```
sudo apt install novnc tigervnc-standalone-server
```

```
cp /usr/share/novnc/vnc.html /usr/share/novnc/index.html
```

#### Installing Xfce desktop environment

Packages for the latest Xfce desktop environment and the TightVNC package available from the official Ubuntu repository. Both Xfce and TightVNC are known for being lightweight and fast, which will help ensure that the VNC connection will be smooth and stable even on slower internet connections.
```
sudo apt install xfce4 xfce4-goodies 
```

#### Starting vncserver
```
vncserver
```
You’ll be prompted to enter and verify a password to access your machine remotely:
<img width="736" alt="Screenshot 2023-03-05 at 10 58 25 PM" src="https://user-images.githubusercontent.com/30818966/222976171-f3fb79cb-ef65-40cc-8866-3a23414d0f37.png">


Launching novnc
```
/usr/share/novnc/utils/launch.sh --vnc 127.0.0.1:5901 --listen 6080
```



![image](https://user-images.githubusercontent.com/30818966/222971558-2cd26002-633e-47c4-862b-47371cdef967.png)



## Writing crontab for ttyd and noVNC

Crontab (CRON TABle) is a file which contains the schedule of cron entries to be run and at specified times.

```
sudo vim /etc/crontab
```

Add your  command as shown in the image below

![image](https://user-images.githubusercontent.com/30818966/222971787-3813d848-e257-4ad0-b364-4483fa5657b1.png)


## License

[MIT](https://choosealicense.com/licenses/mit/)
