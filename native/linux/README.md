# Native Linux Components

This directory contains Linux-native service definitions and scripts.

## Structure

```
native/linux/
├── bin/           # Entry point scripts (vnc-remote)
├── lib/           # Bash module library (symlink to src/lib/)
└── systemd/       # systemd unit files
    ├── vnc-remote-vnc.service
    ├── vnc-remote-novnc.service
    ├── vnc-remote-ttyd.service
    └── vnc-remote-health.service
```

## systemd Units

Install with:
```bash
make install-systemd
# or
sudo bash scripts/install_systemd.sh
```

Manage with:
```bash
make systemd-start
make systemd-stop
make systemd-status
```

## Bash Modules

The Bash module library lives at `src/lib/` and is the implementation for
Linux-native operations (tigervncserver, nginx, fail2ban, apt-get, useradd).
The `native/linux/lib/` directory is a convenience alias.
