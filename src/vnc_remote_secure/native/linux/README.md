# Native Linux Components

This directory contains Linux-native service definitions and scripts.

## Structure

```
src/vnc_remote_secure/native/linux/
├── bin/           # Entry point scripts (vnc-remote)
└── systemd/       # systemd unit files
    └── vnc-remote.service   # Unified service (runs the Python service manager)
```

## systemd Units

The project ships a single unified `vnc-remote.service` unit that runs the
Python service manager, which in turn supervises VNC, noVNC, ttyd, health,
and landing as child processes. Per-service split units may be added in the
future; until then, use the unified unit.

Install with:
```bash
make install-systemd
# or
sudo bash scripts/maintenance/install_systemd.sh
```

Manage with:
```bash
make systemd-start
make systemd-stop
make systemd-status
```

## Linux-Native Operations

All Linux-native operations (tigervncserver, nginx, fail2ban, apt-get,
useradd) are implemented in the Python package under
`src/vnc_remote_secure/platform/linux/`. The Bash entry point
`src/rpi-vnc-remote.sh` is a thin wrapper that delegates to the Python CLI.
