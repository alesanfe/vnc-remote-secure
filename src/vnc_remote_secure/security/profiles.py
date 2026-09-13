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
    trusted-lan       — Trusted LAN, self-signed TLS, nginx public
    private-overlay   — Private overlay network (VPN), nginx public
    public-hardened   — Public internet, Let's Encrypt, MFA, strict

Legacy aliases (backwards-compatible):
    home-lan          → trusted-lan
    private-vpn        → private-overlay
    internet-hardened  → public-hardened
    local-only         → development
"""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def _is_tls_enabled() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    Bash uses DISABLE_SSL (negative logic); Python uses TLS_ENABLED
    (positive logic). This reads both so a single .env file works.
    """
    tls_val = os.environ.get('TLS_ENABLED', '').strip()
    if tls_val:
        return tls_val.lower() in ('true', '1', 'yes')
    disable_val = os.environ.get('DISABLE_SSL', '').strip()
    if disable_val:
        return disable_val.lower() not in ('true', '1', 'yes')
    return True


# Backends ALWAYS bind to 127.0.0.1 regardless of profile.
# Only nginx may bind to PUBLIC_BIND_HOST (0.0.0.0 in LAN/VPN profiles).
# This is the Zero Trust control plane: no service is reachable without
# passing through the authenticated reverse proxy.
BACKEND_BIND_HOST = '127.0.0.1'

PROFILES = {
    'development': {
        'description': 'Local development and testing (localhost only)',
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
    'trusted-lan': {
        'description': 'Trusted LAN with self-signed TLS via nginx (was home-lan)',
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
    'private-overlay': {
        'description': 'Private overlay network (was private-vpn)',
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
    'public-hardened': {
        'description': 'Public internet with maximum security (was internet-hardened)',
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

# Backwards-compatible aliases for renamed profiles.
# Old name -> new name. Allows existing .env files to keep working.
_PROFILE_ALIASES = {
    'home-lan': 'trusted-lan',
    'private-vpn': 'private-overlay',
    'internet-hardened': 'public-hardened',
    'local-only': 'development',
}


def get_profile() -> str:
    """Return the active security profile name."""
    return os.environ.get('SECURITY_PROFILE', 'development')


def get_profile_config(profile: Optional[str] = None) -> dict:
    """Return the configuration dict for a profile.

    Falls back to 'development' if the requested profile doesn't exist.
    Supports backwards-compatible aliases for renamed profiles.
    """
    name = profile or get_profile()
    # Resolve legacy profile names to their new equivalents
    name = _PROFILE_ALIASES.get(name, name)
    if name not in PROFILES:
        logger.warning("Unknown security profile '%s', using 'development'", name)
        name = 'development'
    return PROFILES[name].copy()


def apply_profile(profile: Optional[str] = None, overwrite: bool = False):
    """Apply a security profile to the current process environment.

    Sets env vars from the profile. Existing env vars are preserved
    unless ``overwrite`` is True (user-configured values take priority
    over profile defaults).

    Security-critical variables (BACKEND_BIND_HOST) are always enforced
    in hardened profiles, regardless of user overrides. This prevents
    accidental exposure of internal services.
    """
    config = get_profile_config(profile)
    resolved = _PROFILE_ALIASES.get(profile or get_profile(), profile or get_profile())

    # Security-critical variables that are always enforced in hardened profiles.
    locked_vars = {'BACKEND_BIND_HOST': '127.0.0.1'}
    is_hardened = resolved in ('public-hardened', 'private-overlay', 'trusted-lan')

    for key, value in config.items():
        if key == 'description':
            continue
        # Enforce locked vars in hardened profiles, even if user set them.
        if is_hardened and key in locked_vars:
            os.environ[key] = locked_vars[key]
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
    profile = _PROFILE_ALIASES.get(get_profile(), get_profile())
    tls = _is_tls_enabled()
    bind = os.environ.get('BIND_HOST', '127.0.0.1')
    nginx = os.environ.get('NGINX_ENABLED', 'false').lower() in ('true', '1', 'yes')
    mfa = os.environ.get('MFA_REQUIRED', 'false').lower() in ('true', '1', 'yes')

    if not tls and bind == '0.0.0.0' and not nginx:
        warnings.append(
            'TLS disabled but services bind to 0.0.0.0 without nginx. '
            'Internal services are exposed without encryption.'
        )
    if not tls and profile == 'public-hardened':
        warnings.append(
            'TLS disabled in public-hardened profile. This is unsafe.'
        )
    if not mfa and profile == 'public-hardened':
        warnings.append(
            'MFA not required in public-hardened profile. '
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
    profile = _PROFILE_ALIASES.get(get_profile(), get_profile())
    tls = _is_tls_enabled()
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

    # public-hardened requires TLS + MFA + nginx.
    if profile == 'public-hardened':
        if not tls:
            blockers.append({
                'code': 'NO_TLS_PUBLIC',
                'message': 'TLS is disabled in public-hardened profile.',
            })
        if not mfa:
            blockers.append({
                'code': 'NO_MFA_PUBLIC',
                'message': 'MFA is not required in public-hardened profile.',
            })
        if not nginx:
            blockers.append({
                'code': 'NO_REVERSE_PROXY_PUBLIC',
                'message': 'nginx is not enabled in public-hardened profile. '
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
