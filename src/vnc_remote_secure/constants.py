"""Project-wide constants (re-exported from core.constants).

This module is kept at the package root for convenient access:
    from vnc_remote_secure.constants import APP_NAME, APP_VERSION
"""
from vnc_remote_secure.core.constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_VNC_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_VNC_GEOMETRY,
    DEFAULT_VNC_DEPTH,
    MIN_PASSWORD_LENGTH,
    WEAK_PASSWORDS,
    RESERVED_USERNAMES,
)

__all__ = [
    'APP_NAME',
    'APP_VERSION',
    'DEFAULT_VNC_PORT',
    'DEFAULT_NOVNC_PORT',
    'DEFAULT_TTYD_PORT',
    'DEFAULT_HEALTH_PORT',
    'DEFAULT_LANDING_PORT',
    'DEFAULT_VNC_GEOMETRY',
    'DEFAULT_VNC_DEPTH',
    'MIN_PASSWORD_LENGTH',
    'WEAK_PASSWORDS',
    'RESERVED_USERNAMES',
]
