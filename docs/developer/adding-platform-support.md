# Adding Platform Support

This guide explains how to add support for a new platform in VNC Remote Secure.

## Architecture

Platform-specific code lives in `src/vnc_remote_secure/platform/`. Each platform
implements the `PlatformAdapter` interface defined in `src/vnc_remote_secure/platform/base.py`.

## Steps

### 1. Create the platform package

```
src/vnc_remote_secure/platform/<platform>/
├── __init__.py
├── adapter.py       # Main adapter class (required)
├── firewall.py      # Firewall management (optional, platform-specific)
├── installer.py     # Installation logic
├── permissions.py   # Permission management
├── services.py      # Service management (optional, platform-specific)
└── users.py         # User management
```

Note: Not all modules are required for every platform. For example,
Linux has `services.py` but no `firewall.py`, while Windows has
`firewall.py` but no `services.py`. Implement only the modules that
make sense for the target platform.

### 2. Implement the adapter

```python
from vnc_remote_secure.platform.base import PlatformAdapter

class MyPlatformAdapter(PlatformAdapter):
    def get_platform_info(self):
        return {'platform': 'myplatform', ...}

    def start_vnc_server(self, display, geometry, depth, password):
        ...

    def get_lan_ips(self):
        ...

    # Implement all other methods from PlatformAdapter
    # (remove_service, install/remove_firewall_rule,
    #  create/remove_runtime_user, get_audio_capture_cmd,
    #  list_audio_devices, create_gamepad_injector)...
```

### 3. Register in detection

Update `src/vnc_remote_secure/platform/base.py` `get_adapter()`:

```python
def get_adapter():
    """Detect platform and return the appropriate adapter instance."""
    import platform
    system = platform.system().lower()
    if system == 'windows':
        from vnc_remote_secure.platform.windows.adapter import WindowsAdapter
        return WindowsAdapter()
    elif system == 'myplatform':
        from vnc_remote_secure.platform.myplatform.adapter import MyPlatformAdapter
        return MyPlatformAdapter()
    else:
        from vnc_remote_secure.platform.linux.adapter import LinuxAdapter
        return LinuxAdapter()
```

### 4. Create native components

If the platform has native service management (like systemd or Windows Services),
create the corresponding files in `src/vnc_remote_secure/native/<platform>/`.

### 5. Add tests

Create test files in:
- `tests/unit/` - Unit tests for platform modules
- `tests/integration/<platform>/` - Integration tests
- `tests/e2e/<platform>/` - End-to-end tests

### 6. Update CI

Add the new platform to `.github/workflows/ci.yml` and `integration.yml`.

### 7. Update documentation

- `docs/installation/<platform>.md` - Installation guide
- `docs/architecture/components.md` - Architecture overview
- `README.md` - Compatibility matrix
