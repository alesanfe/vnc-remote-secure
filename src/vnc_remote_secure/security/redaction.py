"""Secret redaction utilities for logs and diagnostic output.

Provides centralized redaction so that secrets never appear in logs,
doctor output, or API responses. Shows only ``configured`` or a
partial fingerprint, never the full value.
"""
import hashlib
import os

from vnc_remote_secure.core.config import load_env_file

# Secret variable names that should never be printed in full
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
    'DISCORD_WEBHOOK_URL',
    'ALERT_SMTP_PASSWORD',
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
    """Redact an environment variable for safe display."""
    load_env_file()
    value = os.environ.get(name, '')
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

    Each entry is either 'configured' or 'empty'.
    """
    load_env_file()
    return {
        name: redact_value(name, os.environ.get(name, ''))
        for name in sorted(SECRET_VARS)
    }
