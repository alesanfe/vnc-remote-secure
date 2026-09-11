# Adding Platform Support

This guide explains how to add support for a new platform in VNC Remote Secure.

## Architecture

Platform-specific code lives in `src/vnc_remote_secure/platform/`. Each platform
implements the `PlatformAdapter` interface defined in `platform/base.py`.

## Steps

### 1. Create the platform package

```
src/vnc_remote_secure/platform/<platform>/
├── __init__.py
├── adapter.py       # Main adapter class
├── dependencies.py  # Dependency checking
├── firewall.py      # Firewall management
├── installer.py     # Installation logic
├── permissions.py   # Permission management
├── services.py      # Service management
└── users.py         # User management
```

### 2. Implement the adapter

```python
from vnc_remote_secure.platform.base import PlatformAdapter

class MyPlatformAdapter(PlatformAdapter):
    def get_platform_info(self):
        return {'platform': 'myplatform', ...}

    def install_service(self, service_definition):
        ...

    # Implement all other methods...
```

### 3. Register in detection

Update `src/vnc_remote_secure/platform/detection.py`:

```python
def detect_platform():
    system = platform.system().lower()
    if system == 'myplatform':
        return 'myplatform'
    ...
```

Update `src/vnc_remote_secure/platform/base.py` `get_adapter()`:

```python
def get_adapter():
    p = detect_platform()
    if p == 'myplatform':
        from vnc_remote_secure.platform.myplatform.adapter import MyPlatformAdapter
        return MyPlatformAdapter()
    ...
```

### 4. Create native components

If the platform has native service management (like systemd or Windows Services),
create the corresponding files in `native/<platform>/`.

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
