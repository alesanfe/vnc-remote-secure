"""Security profiles for VNC Remote Secure.

Provides coherent security configuration presets instead of dozens of
independent environment variables. Each profile sets a consistent set
of defaults that avoid contradictory configurations (e.g. SSL disabled
but ports publicly exposed).

Key principle (Zero Trust): backends NEVER bind to 0.0.0.0. Only the
reverse proxy (nginx) may bind publicly. This prevents bypassing the
authentication gateway by connecting directly to noVNC, terminal, or
health ports.

Profiles:
    development       — Local testing, no TLS, localhost only
    home-lan          — Home network, self-signed TLS, nginx public
    private-vpn        — Behind Tailscale/WireGuard, nginx public
    internet-hardened  — Public internet, Let's Encrypt, MFA, strict
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# Backends ALWAYS bind to 127.0.0.1 regardless of profile.
# Only nginx may bind to PUBLIC_BIND_HOST (0.0.0.0 in LAN/VPN profiles).
# This is the Zero Trust control plane: no service is reachable without
# passing through the authenticated reverse proxy.
BACKEND_BIND_HOST = '127.0.0.1'

PROFILES = {
    'development': {
        'description': 'Local development and testing',
        'TLS_ENABLED': 'false',
        'BIND_HOST': '127.0.0.1',
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '127.0.0.1',
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
        'description': 'Home network with self-signed TLS via nginx',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '127.0.0.1',
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '0.0.0.0',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'LANDING_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'true',
        'MFA_REQUIRED': 'false',
        'SESSION_IDLE_TIMEOUT': '1800',
        'SESSION_MAX_LIFETIME': '28800',
        'AUTH_MAX_ATTEMPTS': '5',
    },
    'private-vpn': {
        'description': 'Behind Tailscale/WireGuard, nginx public to VPN',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '127.0.0.1',
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '0.0.0.0',
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
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '0.0.0.0',
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


def get_blocking_findings() -> list:
    """Return critical findings that BLOCK deployment.

    Unlike ``validate_profile_consistency`` (warnings), these are
    hard blockers: the system must refuse to start in internet-hardened
    mode if any of these are present.

    Returns a list of blocking finding dicts with 'code' and 'message'.
    """
    blockers = []
    profile = get_profile()
    tls = os.environ.get('TLS_ENABLED', 'true').lower() in ('true', '1', 'yes')
    bind = os.environ.get('BIND_HOST', '127.0.0.1')
    mfa = os.environ.get('MFA_REQUIRED', 'false').lower() in ('true', '1', 'yes')
    nginx = os.environ.get('NGINX_ENABLED', 'false').lower() in ('true', '1', 'yes')

    # Backends must NEVER bind to 0.0.0.0 — only nginx may.
    if bind == '0.0.0.0':
        blockers.append({
            'code': 'BACKEND_PUBLIC_BIND',
            'message': (
                'BIND_HOST is 0.0.0.0 — backends are directly reachable, '
                'bypassing the authentication gateway. Set BIND_HOST=127.0.0.1 '
                'and use PUBLIC_BIND_HOST for nginx.'
            ),
        })

    # Internet-hardened requires TLS + MFA + nginx.
    if profile == 'internet-hardened':
        if not tls:
            blockers.append({
                'code': 'NO_TLS_PUBLIC',
                'message': 'TLS is disabled in internet-hardened profile.',
            })
        if not mfa:
            blockers.append({
                'code': 'NO_MFA_PUBLIC',
                'message': 'MFA is not required in internet-hardened profile.',
            })
        if not nginx:
            blockers.append({
                'code': 'NO_REVERSE_PROXY_PUBLIC',
                'message': 'nginx is not enabled in internet-hardened profile. '
                           'Backends would be directly exposed.',
            })

    # Default/weak passwords are always a blocker.
    vnc_pass = os.environ.get('VNC_PASSWORD', '')
    if vnc_pass in ('', 'changeme', 'admin123', 'YourStrongPassword123', 'password'):
        blockers.append({
            'code': 'WEAK_VNC_PASSWORD',
            'message': 'VNC_PASSWORD is empty or uses a known default value.',
        })

    return blockers


def is_deployment_blocked() -> bool:
    """Return True if deployment must be blocked due to critical findings."""
    return len(get_blocking_findings()) > 0
