"""Secret redaction utilities for logs and diagnostic output.

Provides centralized redaction so that secrets never appear in logs,
doctor output, or API responses. Shows only ``configured`` or a
partial fingerprint, never the full value.
"""
import hashlib
import logging
import os

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)

# Secret variable names that should never be printed in full.
# CANONICAL list — config_inspector.CREDENTIAL_VARS aliases this set
# so new secrets only have to be added here once (the two lists had
# already drifted apart once and leaked LANDING_PASSWORD).
SECRET_VARS = {
    'TTYD_PASSWD',
    'TEMP_USER_PASS',
    'VNC_PASSWORD',
    'USER_UI_PASSWORD',
    'LANDING_PASSWORD',
    'HEALTH_AUTH_TOKEN',
    'DUCKDNS_TOKEN',
    'AUTH_SECRET',
    'FLASK_SECRET_KEY',
    'TOTP_SECRET',
    'RECOVERY_CODES_HASHES',
    'BACKUP_PASSWORD',
    'DISCORD_WEBHOOK_URL',
    'ALERT_WEBHOOK_URL',
    'ALERT_SMTP_PASS',
    'SSL_KEY',
}


def redact_value(name: str, value: str, show_fingerprint: bool = False) -> str:
    """Redact a secret value for safe display.

    Args:
        name: The variable name (used to determine if it's a secret).
        value: The value to redact.
        show_fingerprint: If True, show a short hash fingerprint.

    Returns:
        'configured' if value is non-empty, 'empty' if empty,
        or a fingerprint like 'configured (sha256:abc123)' if requested.
    """
    if not value:
        return 'empty'
    if name.upper() not in SECRET_VARS:
        return value  # Not a secret, return as-is
    if show_fingerprint:
        fp = hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]
        return f'configured (sha256:{fp})'
    return 'configured'


def redact_env(name: str, show_fingerprint: bool = False) -> str:
    """Redact an environment variable for safe display.

    Falls back to the persisted generated credential — the same
    resolution ``secret_status`` uses, so ``secrets redact`` and
    ``secrets status`` cannot disagree about whether a credential is
    configured.
    """
    load_env_file()
    value = os.environ.get(name, '')
    if not value and name.upper() in SECRET_VARS:
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )
            value = _load_generated_credential(name) or ''
        except (ImportError, OSError):
            logger.debug(
                "Generated credential lookup failed for %s", name,
                exc_info=True)
    return redact_value(name, value, show_fingerprint)


def redact_dict(data: dict, show_fingerprint: bool = False) -> dict:
    """Redact all secret values in a dict (recursively).

    Non-secret keys are returned unchanged.
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = redact_dict(value, show_fingerprint)
        elif isinstance(key, str) and key.upper() in SECRET_VARS:
            result[key] = redact_value(key, str(value), show_fingerprint)
        else:
            result[key] = value
    return result


def redact_text(text: str) -> str:
    """Redact known secret patterns in arbitrary text.

    Useful for log scrubbing. Replaces values that look like secrets
    with '[REDACTED]'.
    """
    if not text:
        return text
    load_env_file()
    result = text
    for var_name in SECRET_VARS:
        value = os.environ.get(var_name, '')
        if value and len(value) >= 4 and value in result:
            result = result.replace(value, '[REDACTED]')
    return result


def get_secret_status() -> dict:
    """Return a status dict of all known secrets (no values).

    Each entry is either 'configured' or 'empty'. For secrets that are
    persisted to the runtime directory (AUTH_SECRET, FLASK_SECRET_KEY),
    the persisted file is also checked so the status reflects reality
    even when the value is not in the current process environment.
    """
    load_env_file()
    status = {}
    for name in sorted(SECRET_VARS):
        val = os.environ.get(name, '')
        if not val and name in ('AUTH_SECRET', 'FLASK_SECRET_KEY'):
            # _get_secret() resolves AUTH_SECRET || FLASK_SECRET_KEY ||
            # persisted auth_secret.key — the two names share one chain,
            # so either being set means both are effectively configured,
            # and a persisted file counts for both.
            other = 'FLASK_SECRET_KEY' if name == 'AUTH_SECRET' else 'AUTH_SECRET'
            if os.environ.get(other, ''):
                val = '<shared>'
            else:
                try:
                    from vnc_remote_secure.security.authentication import _secret_file_path
                    if os.path.exists(_secret_file_path()):
                        val = '<persisted>'
                except (ImportError, OSError):
                    logger.debug("Failed to check persisted secret file", exc_info=True)
        if not val and name in (
                'VNC_PASSWORD', 'TTYD_PASSWD', 'LANDING_PASSWORD'):
            # Auto-generated credentials persist to
            # generated_credentials.env — report them as configured or
            # `secrets status` claims the deployment has no password
            # while services are in fact enforcing one.
            try:
                from vnc_remote_secure.core.config import (
                    _load_generated_credential,
                )
                if _load_generated_credential(name):
                    val = '<generated>'
            except (ImportError, OSError):
                logger.debug("Failed to check generated credential", exc_info=True)
        status[name] = redact_value(name, val)
    return status


def sanitized_child_env() -> dict:
    """Return a copy of ``os.environ`` without credential variables.

    For external helper processes (websockify, ffmpeg, the VNC server
    binary) that perform no auth and need none of our secrets. On any
    internal error this returns a minimal PATH/SYSTEM-only environment
    instead of ``None`` - passing ``env=None`` to Popen would inherit
    the FULL environment including every secret, which is the failure
    this function exists to prevent.
    """
    import os as _os
    try:
        return {k: v for k, v in _os.environ.items()
                if k not in SECRET_VARS}
    except Exception:  # noqa: BLE001 - fail closed, not env=None
        minimal = {}
        for k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC',
                  'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL'):
            v = _os.environ.get(k)
            if v:
                minimal[k] = v
        return minimal
