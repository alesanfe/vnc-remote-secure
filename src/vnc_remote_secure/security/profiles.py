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
    development       — Local testing, no TLS, 127.0.0.1 only
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

from vnc_remote_secure.core.constants import (
    DEFAULT_LANDING_PORT,
    DEFAULT_SESSION_SAMESITE,
    WEAK_PASSWORDS,
)

logger = logging.getLogger(__name__)


def _is_tls_enabled() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    Bash uses DISABLE_SSL (negative logic); Python uses TLS_ENABLED
    (positive logic). This reads both so a single .env file works.

    This is the single source of truth for TLS resolution: ``config.py``
    and ``profiles.py`` both delegate here so there is one interpretation
    of ``--no-ssl`` / ``TLS_ENABLED`` / ``DISABLE_SSL`` across the whole
    stack.
    """
    from vnc_remote_secure.core.config import _is_tls_enabled_env
    return _is_tls_enabled_env()


# Backends ALWAYS bind to 127.0.0.1 regardless of profile.
# Only nginx may bind to PUBLIC_BIND_HOST (0.0.0.0 in LAN/VPN profiles).
# This is the Zero Trust control plane: no service is reachable without
# passing through the authenticated reverse proxy.
BACKEND_BIND_HOST = '127.0.0.1'

PROFILES = {
    'development': {
        'description': 'Local development and testing (127.0.0.1 only)',
        'TLS_ENABLED': 'false',
        'BIND_HOST': '127.0.0.1',
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '127.0.0.1',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'false',
        'MFA_REQUIRED': 'false',
        'SESSION_IDLE_TIMEOUT': '3600',
        'SESSION_MAX_LIFETIME': '86400',
        'AUTH_MAX_ATTEMPTS': '10',
        'ALLOWED_ORIGINS': f'http://127.0.0.1:{DEFAULT_LANDING_PORT}',
    },
    'trusted-lan': {
        'description': 'Trusted LAN with self-signed TLS via nginx (was home-lan)',
        'TLS_ENABLED': 'true',
        'BIND_HOST': '127.0.0.1',
        'BACKEND_BIND_HOST': '127.0.0.1',
        'PUBLIC_BIND_HOST': '0.0.0.0',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'NGINX_ENABLED': 'true',
        # nginx is the public entry — backends may trust its
        # X-Forwarded-* headers (Host/Proto/For).
        'TRUSTED_PROXY': 'true',
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
        'NGINX_ENABLED': 'true',
        'TRUSTED_PROXY': 'true',
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
        'NGINX_ENABLED': 'true',
        'TRUSTED_PROXY': 'true',
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
    """Return the active security profile name.

    ``VNC_REMOTE_PROFILE`` is honoured as a deprecated fallback when
    ``SECURITY_PROFILE`` is unset — it is documented as an alias
    (configuration.md) and still written by the PowerShell start
    wrapper, so ignoring it would silently downgrade an operator's
    chosen profile to ``development``.
    """
    return (os.environ.get('SECURITY_PROFILE')
            or os.environ.get('VNC_REMOTE_PROFILE')
            or 'development')


def resolve_profile() -> str:
    """Return the canonical (alias-resolved) active profile name.

    Every consumer that needs the *effective* profile — hardened checks,
    lock lookups, fallback decisions — must use this instead of reading
    ``SECURITY_PROFILE`` directly: the raw env var still reports legacy
    names (``home-lan``) and misses the ``VNC_REMOTE_PROFILE`` fallback,
    so two readers would disagree on the same deployment.
    """
    name = get_profile()
    return _PROFILE_ALIASES.get(name, name)


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


def locked_vars_for(profile: Optional[str] = None) -> dict:
    """Return the env vars a hardened profile force-enforces.

    This is the single source of truth for the lock set used by
    :func:`apply_profile` — ``config_inspector`` consumes it so
    ``config show-effective`` reports the same overridden values the
    runtime will actually apply. Returns ``{}`` for non-hardened
    profiles.
    """
    resolved = _PROFILE_ALIASES.get(profile or get_profile(), profile or get_profile())
    if resolved not in ('public-hardened', 'private-overlay', 'trusted-lan'):
        return {}
    locked = {
        'BACKEND_BIND_HOST': '127.0.0.1',
        'TLS_ENABLED': 'true',
        'DISABLE_SSL': 'false',
        'NGINX_ENABLED': 'true',
        # Per-service bind hosts: BACKEND_BIND_HOST alone does not cover
        # these — an operator-set ``USER_UI_HOST=0.0.0.0`` (or any
        # *_HOST var) would bind that backend publicly in a hardened
        # profile, bypassing the nginx gateway and its auth model.
        'USER_UI_HOST': '127.0.0.1',
        'NOVNC_HOST': '127.0.0.1',
        'TTYD_HOST': '127.0.0.1',
        'HEALTH_WEB_HOST': '127.0.0.1',
        'AUDIO_STREAM_HOST': '127.0.0.1',
        'GAMEPAD_HOST': '127.0.0.1',
        'SERVE_NOVNC_HOST': '127.0.0.1',
        # The websockify bridge and the VNC RFB listener bind loopback
        # unconditionally in code (service_manager._start_websockify /
        # the platform VNC adapters) — no *_HOST var exists to lock.
    }
    # LANDING_HOST is the exception: on Windows the landing portal IS
    # the public gateway (nginx is not supported), so it legitimately
    # binds PUBLIC_BIND_HOST there. On Linux it stays loopback behind
    # nginx.
    import platform as _platform
    if _platform.system() != 'Windows':
        locked['LANDING_HOST'] = '127.0.0.1'
    # MFA is locked only when the profile itself mandates it —
    # trusted-lan deliberately allows MFA_REQUIRED=false (its own
    # profile value), so forcing the lock there would contradict both
    # the profile definition and ``validate_config``, which only
    # requires MFA for public-hardened and private-overlay.
    config = get_profile_config(resolved)
    if config.get('MFA_REQUIRED', '').lower() in ('true', '1', 'yes'):
        locked['MFA_REQUIRED'] = 'true'
    return locked


def apply_profile(profile: Optional[str] = None, overwrite: bool = False):
    """Apply a security profile to the current process environment.

    Sets env vars from the profile. Existing env vars are preserved
    unless ``overwrite`` is True (user-configured values take priority
    over profile defaults).

    Security-critical variables (see :func:`locked_vars_for`) are always
    enforced in hardened profiles, regardless of user overrides. This
    prevents accidental exposure of internal services.
    """
    config = get_profile_config(profile)
    resolved = _PROFILE_ALIASES.get(profile or get_profile(), profile or get_profile())

    # Security-critical variables that are always enforced in hardened
    # profiles. A user-set ``TLS_ENABLED=false`` / ``DISABLE_SSL=true``
    # / ``NGINX_ENABLED=false`` must NOT survive — these are exactly
    # the knobs an attacker (or an accidental misconfiguration) would
    # flip to weaken a deployment that explicitly opted into a
    # hardened posture. The same set is what ``config validate``
    # flags as critical for these profiles.
    locked_vars = locked_vars_for(resolved)
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
    # Locked vars not present in the profile config (e.g. DISABLE_SSL
    # is an env-only negative-logic flag) are still enforced.
    if is_hardened:
        for key, value in locked_vars.items():
            if os.environ.get(key) != value:
                os.environ[key] = value
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
    if mfa and not os.environ.get('TOTP_SECRET') \
            and not os.environ.get('RECOVERY_CODES_HASHES'):
        warnings.append(
            'MFA_REQUIRED=true but neither TOTP_SECRET nor '
            'RECOVERY_CODES_HASHES is configured — every login will '
            'fail MFA. Set TOTP_SECRET.'
        )
    if nginx and not tls:
        warnings.append(
            'nginx enabled but TLS disabled. nginx will serve HTTP only.'
        )
    if os.environ.get('SESSION_SAMESITE', DEFAULT_SESSION_SAMESITE) == 'None' and not tls:
        warnings.append(
            'SESSION_SAMESITE=None without TLS: browsers reject '
            'SameSite=None cookies that lack the Secure attribute — '
            'every login will silently fail. Enable TLS or use '
            'SESSION_SAMESITE=Lax.'
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

    # TLS-enabled profiles must also resolve actual certs — the flag
    # alone does not encrypt anything when no cert/key pair exists
    # (services would silently serve cleartext HTTP).
    if tls and profile != 'development':
        try:
            from vnc_remote_secure.security.certificates import create_ssl_context
            if create_ssl_context() is None:
                blockers.append({
                    'code': 'TLS_CERT_MISSING',
                    'message': (
                        'TLS is enabled but no cert/key pair could be '
                        'resolved (SSL_CERT/SSL_KEY env, canonical ssl '
                        'dir, or data/ssl). Services would run in '
                        'cleartext.'),
                })
        except ImportError:
            pass

    # Default/weak passwords are always a blocker — but only for
    # credentials backing a feature that is actually enabled. Requiring
    # a strong password for a disabled service would block startups for
    # no security benefit (e.g. USER_UI_ENABLED=false).
    weak_lower = {p.lower() for p in WEAK_PASSWORDS}
    user_ui_on = os.environ.get(
        'USER_UI_ENABLED', 'false').lower() in ('true', '1', 'yes')

    def _check_secret(env_name: str, code: str, label: str) -> None:
        value = os.environ.get(env_name, '')
        if not value:
            # Auto-generated credentials persisted by get_config()
            # (generated_credentials.env) count as configured — the
            # blocker must mirror the resolution services actually do
            # or a generated credential reports a false blocker when
            # this check runs before get_config() in the process.
            try:
                from vnc_remote_secure.core.config import (
                    _load_generated_credential,
                )
                value = _load_generated_credential(env_name)
            except Exception:  # noqa: BLE001 - fallback is best-effort
                value = ''
        if value == '' or value.lower() in weak_lower:
            blockers.append({
                'code': code,
                'message': f'{label} is empty or uses a known default value.',
            })

    _check_secret('VNC_PASSWORD', 'WEAK_VNC_PASSWORD', 'VNC_PASSWORD')
    _check_secret('TTYD_PASSWD', 'WEAK_TTYD_PASSWORD', 'TTYD_PASSWD')
    if user_ui_on:
        _check_secret('USER_UI_PASSWORD', 'WEAK_USER_UI_PASSWORD', 'USER_UI_PASSWORD')
    _check_secret('LANDING_PASSWORD', 'WEAK_LANDING_PASSWORD', 'LANDING_PASSWORD')

    # Flask session signing key: hardened profiles must not start with an
    # ephemeral auto-generated secret because it invalidates sessions on
    # every restart and breaks multi-process deployments.
    if profile in ('public-hardened', 'private-overlay', 'trusted-lan'):
        flask_key = os.environ.get('FLASK_SECRET_KEY', '')
        if flask_key == '' or flask_key.lower() in weak_lower:
            blockers.append({
                'code': 'WEAK_FLASK_SECRET',
                'message': 'FLASK_SECRET_KEY is empty or weak in a hardened profile.',
            })
        # Backups contain secrets (.env, SSL keys) and must be encrypted
        # in hardened profiles. BACKUP_PASSWORD must be set.
        backup_pw = os.environ.get('BACKUP_PASSWORD', '')
        if not backup_pw:
            blockers.append({
                'code': 'MISSING_BACKUP_PASSWORD',
                'message': 'BACKUP_PASSWORD is not set in a hardened profile. '
                           'Backups contain secrets and must be encrypted.',
            })

    return blockers


def is_deployment_blocked() -> bool:
    """Return True if deployment must be blocked due to critical findings."""
    return len(get_blocking_findings()) > 0
