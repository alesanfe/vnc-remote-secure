"""Security profiles for VNC Remote Secure.

Provides coherent security configuration presets instead of dozens of
independent environment variables. Each profile sets a consistent set
of defaults that avoid contradictory configurations (e.g. SSL disabled
but ports publicly exposed).

Profiles:
    development       — Local testing, no TLS, localhost only
    home-lan          — Home network, self-signed TLS, LAN access
    private-vpn        — Behind Tailscale/WireGuard, no public exposure
    internet-hardened  — Public internet, Let's Encrypt, MFA, strict
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


PROFILES = {
    'development': {
        'description': 'Local development and testing',
        'TLS_ENABLED': 'false',
        'BIND_HOST': '127.0.0.1',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'LANDING_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'false',
        'MFA_REQUIRED': 'false',
        'SESSION_IDLE_TIMEOUT': '3600',
        'SESSION_MAX_LIFETIME': '86400',
        'AUTH_MAX_ATTEMPTS': '10',
        'ALLOWED_ORIGINS': 'http://localhost:8000,http://127.0.0.1:8000',
    },
    'home-lan': {
        'description': 'Home network with self-signed TLS',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '0.0.0.0',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'LANDING_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'true',
        'MFA_REQUIRED': 'false',
        'SESSION_IDLE_TIMEOUT': '1800',
        'SESSION_MAX_LIFETIME': '28800',
        'AUTH_MAX_ATTEMPTS': '5',
    },
    'private-vpn': {
        'description': 'Behind Tailscale/WireGuard, no public exposure',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '0.0.0.0',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'LANDING_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'true',
        'MFA_REQUIRED': 'true',
        'SESSION_IDLE_TIMEOUT': '900',
        'SESSION_MAX_LIFETIME': '14400',
        'AUTH_MAX_ATTEMPTS': '5',
    },
    'internet-hardened': {
        'description': 'Public internet with maximum security',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '127.0.0.1',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'LANDING_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'true',
        'MFA_REQUIRED': 'true',
        'SESSION_IDLE_TIMEOUT': '900',
        'SESSION_MAX_LIFETIME': '28800',
        'AUTH_MAX_ATTEMPTS': '3',
        'AUTH_LOCKOUT_SECONDS': '1800',
        'ALLOWED_ORIGINS': '',  # Must be set explicitly via DUCK_DOMAIN
    },
}


def get_profile() -> str:
    """Return the active security profile name."""
    return os.environ.get('SECURITY_PROFILE', 'development')


def get_profile_config(profile: Optional[str] = None) -> dict:
    """Return the configuration dict for a profile.

    Falls back to 'development' if the requested profile doesn't exist.
    """
    name = profile or get_profile()
    if name not in PROFILES:
        logger.warning("Unknown security profile '%s', using 'development'", name)
        name = 'development'
    return PROFILES[name].copy()


def apply_profile(profile: Optional[str] = None, overwrite: bool = False):
    """Apply a security profile to the current process environment.

    Sets env vars from the profile. Existing env vars are preserved
    unless ``overwrite`` is True (user-configured values take priority
    over profile defaults).
    """
    config = get_profile_config(profile)
    for key, value in config.items():
        if key == 'description':
            continue
        if overwrite or key not in os.environ:
            if value:
                os.environ[key] = value
            elif key in os.environ and overwrite:
                del os.environ[key]
    logger.info("Security profile applied: %s", profile or get_profile())


def validate_profile_consistency() -> list:
    """Check for contradictory configuration combinations.

    Returns a list of warning messages (empty if consistent).
    """
    warnings = []
    profile = get_profile()
    tls = os.environ.get('TLS_ENABLED', 'true').lower() in ('true', '1', 'yes')
    bind = os.environ.get('BIND_HOST', '127.0.0.1')
    nginx = os.environ.get('NGINX_ENABLED', 'false').lower() in ('true', '1', 'yes')
    mfa = os.environ.get('MFA_REQUIRED', 'false').lower() in ('true', '1', 'yes')

    if not tls and bind == '0.0.0.0' and not nginx:
        warnings.append(
            'TLS disabled but services bind to 0.0.0.0 without nginx. '
            'Internal services are exposed without encryption.'
        )
    if not tls and profile == 'internet-hardened':
        warnings.append(
            'TLS disabled in internet-hardened profile. This is unsafe.'
        )
    if not mfa and profile == 'internet-hardened':
        warnings.append(
            'MFA not required in internet-hardened profile. '
            'Set MFA_REQUIRED=true for public exposure.'
        )
    if nginx and not tls:
        warnings.append(
            'nginx enabled but TLS disabled. nginx will serve HTTP only.'
        )
    return warnings
