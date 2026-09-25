"""Secret rotation and hygiene — the shared implementation behind
``vnc-remote secrets ...`` and ``POST /api/v1/secrets/*``.

Transport surfaces (CLI, REST) only validate input and format output;
everything that generates, persists or invalidates secrets lives here
so both management paths behave identically.
"""
import contextlib
import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Any env-var credential can be rotated — the mechanism is identical
# (generate a strong value, persist to .env).
ROTATABLE = {
    'TTYD_PASSWD', 'TEMP_USER_PASS', 'VNC_PASSWORD',
    'HEALTH_AUTH_TOKEN', 'LANDING_PASSWORD', 'USER_UI_PASSWORD',
    'AUTH_SECRET', 'FLASK_SECRET_KEY', 'BACKUP_PASSWORD',
}


def generate_secret_value(name: str) -> str:
    """Return a random credential; VNC passwords are capped at 8 chars."""
    import secrets as secrets_mod
    import string

    chars = string.ascii_letters + string.digits + '!@%^&*'
    # VNC legacy DES auth uses at most 8 bytes — a longer rotated
    # value would silently truncate to its first 8 chars, leaving
    # a .env value that does not match the effective credential.
    length = 8 if name == 'VNC_PASSWORD' else 24
    while True:
        new_val = ''.join(secrets_mod.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in new_val)
                and any(c.islower() for c in new_val)
                and any(c.isdigit() for c in new_val)
                and any(c in '!@%^&*' for c in new_val)):
            return new_val


def _drop_stale_secret_fallbacks(name: str) -> None:
    """Remove persisted fallbacks that would resurrect the old value."""
    from vnc_remote_secure.core.config import _remove_generated_credential
    from vnc_remote_secure.security.authentication import _secret_file_path

    # The explicit value now lives in .env — drop the stale generated
    # entry so deleting the env var later does not resurrect the OLD
    # generated password.
    with contextlib.suppress(Exception):  # cleanup is best-effort
        _remove_generated_credential(name)
    # AUTH_SECRET/FLASK_SECRET_KEY share the persisted auth_secret.key
    # file as a fallback — the env var shadows it now, but deleting the
    # env var later would resurrect the OLD key (same stale-fallback bug
    # as generated_credentials.env).
    if name in ('AUTH_SECRET', 'FLASK_SECRET_KEY'):
        with contextlib.suppress(Exception):  # cleanup is best-effort
            if os.path.isfile(_secret_file_path()):
                os.unlink(_secret_file_path())


def rotate_secret(name: str) -> dict:
    """Rotate one env-var credential; returns metadata (never the value).

    Persists the new value into whichever file holds the key (system
    config.env for installed deployments, else project .env), drops
    stale generated fallbacks, and — for operator-facing credentials —
    bumps the operator session epoch so live sessions die with the old
    credential.

    Returns ``{'name', 'fingerprint', 'env_path', 'sessions_revoked'}``.

    Raises ``ValueError`` for a non-rotatable name and ``OSError`` if
    the .env write fails.
    """
    from vnc_remote_secure.core.config import (
        _system_env_path,
        set_env_persistent,
    )
    from vnc_remote_secure.core.paths import find_project_root

    name = str(name or '').strip().upper()
    if name not in ROTATABLE:
        raise ValueError(
            f"cannot rotate '{name}'; rotatable: {sorted(ROTATABLE)}")

    new_val = generate_secret_value(name)

    # Persist the rotation — setting only os.environ would lose the
    # new value when this process exits, and printing it would leak
    # it into scrollback. Running services pick it up on restart.
    if not set_env_persistent(name, new_val):
        raise OSError('could not write .env')

    # Report the real write target, not unconditionally .env.
    sys_env = _system_env_path()
    env_path = sys_env if (
        sys_env and os.path.isfile(sys_env)
        and any(
            ln.split('=', 1)[0].strip() == name
            and not ln.strip().startswith('#')
            for ln in Path(sys_env).read_text(encoding='utf-8').splitlines()
            if '=' in ln)
    ) else os.path.join(find_project_root(), '.env')

    _drop_stale_secret_fallbacks(name)

    sessions_revoked = False
    # Rotating the operator UI credential must kill every live operator
    # session — otherwise a logged-in session keeps working on the OLD
    # password's authority after the credential changed. Bumping the
    # epoch invalidates all sessions issued so far (services pick it up
    # via shared state without a restart).
    if name in ('USER_UI_PASSWORD', 'TTYD_PASSWD'):
        try:
            from vnc_remote_secure.security.sessions import (
                bump_operator_epoch,
            )
            bump_operator_epoch()
            sessions_revoked = True
        except Exception:  # noqa: BLE001 - rotation already succeeded
            pass

    return {
        'name': name,
        'fingerprint': hashlib.sha256(new_val.encode()).hexdigest()[:8],
        'env_path': env_path,
        'sessions_revoked': sessions_revoked,
    }


def secret_status() -> dict:
    """Per-secret status dict (set/missing/weak) — never values."""
    from vnc_remote_secure.security.redaction import get_secret_status
    return get_secret_status()


def redact_secret(name: str) -> str:
    """Return the fingerprinted redaction for one secret."""
    from vnc_remote_secure.security.redaction import redact_env
    return redact_env(name, show_fingerprint=True)


def secrets_check(fix: bool = False) -> list:
    """TLS config + secret-file permission findings (optionally fixed)."""
    findings = []
    try:
        from vnc_remote_secure.security.tls_validation import (
            validate_tls_config,
        )
        findings.extend(validate_tls_config())
    except (ImportError, OSError, ValueError) as e:
        # Validation framework failure is critical, not a warning.
        findings.append({'severity': 'critical',
                         'message': f'TLS validation error: {e}'})
    try:
        from vnc_remote_secure.security.file_permissions import (
            validate_secret_files,
        )
        findings.extend(validate_secret_files())
    except (ImportError, OSError) as e:
        findings.append({'severity': 'critical',
                         'message': f'File permission check error: {e}'})

    if fix:
        findings = _secrets_check_fix(findings)
    return findings


def _secrets_check_fix(findings: list) -> list:
    """Apply permission fixes for findings that carry a file path."""
    from vnc_remote_secure.security.file_permissions import (
        fix_secret_file_permissions,
        validate_secret_files,
    )
    fixed = []
    for f in findings:
        path = f.get('file')
        if not path:
            continue
        fixed.append({'file': path,
                      'fixed': fix_secret_file_permissions(path)})
    # Re-validate after fixing so the report reflects reality.
    remaining = [f for f in findings if not f.get('file')]
    with contextlib.suppress(ImportError, OSError):
        remaining.extend(validate_secret_files())
    return {'remaining': remaining, 'fixed': fixed}


def generate_recovery_codes(count: int = 8) -> list:
    """Generate MFA recovery codes; only their hashes persist.

    Returns the plaintext codes — callers (CLI print, API response)
    show them ONCE; only SHA-256 hashes are persisted via
    ``RECOVERY_CODES_HASHES`` so each code is single-use.
    """
    from vnc_remote_secure.core.config import set_env_persistent
    from vnc_remote_secure.security.mfa import (
        generate_recovery_codes,
        hash_recovery_code,
    )

    codes = generate_recovery_codes(count)
    hashes = ','.join(hash_recovery_code(c) for c in codes)
    if not set_env_persistent('RECOVERY_CODES_HASHES', hashes):
        raise OSError('could not write .env')
    return codes


def rotate_signing_key() -> dict:
    """Rotate the file-backed signing secret with a coexistence window.

    Unlike ``rotate_secret('AUTH_SECRET')`` (hard cutover), the old key
    stays verifiable for the retire window so in-flight sessions and
    share links do not die at once.
    """
    from vnc_remote_secure.security.authentication import (
        rotate_signing_secret,
    )
    ok, err = rotate_signing_secret()
    if not ok:
        raise RuntimeError(err or 'rotation failed')
    return {'rotated': True, 'window_days': 7}
