# native/linux/lib/

This directory contains Bash library modules that are specific to the Linux
platform implementation. These modules are sourced by the main script
`src/rpi-vnc-remote.sh` and provide Linux-native functionality:

- `core/` - Core utilities (logging, validation, config)
- `security/` - Security modules (firewall, fail2ban, SSL)
- `services/` - Service management (systemd, VNC, noVNC, ttyd)

The canonical source for these modules lives in `src/lib/`. This directory
is a placeholder for future platform-specific overrides.
