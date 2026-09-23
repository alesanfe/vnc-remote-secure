"""``secrets`` command: status, rotate, redact, check."""
import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

from vnc_remote_secure.cli._common import _audit_cli, _find_project_root

# Any env-var credential can be rotated — the mechanism is identical
# (generate a strong value, persist to .env).
_ROTATABLE = {
    'TTYD_PASSWD', 'TEMP_USER_PASS', 'VNC_PASSWORD',
    'HEALTH_AUTH_TOKEN', 'LANDING_PASSWORD', 'USER_UI_PASSWORD',
    'AUTH_SECRET', 'FLASK_SECRET_KEY', 'BACKUP_PASSWORD',
}


def _secrets_status(args):
    from vnc_remote_secure.security.redaction import get_secret_status
    status = get_secret_status()
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print("Secret status:")
        for name, val in status.items():
            print(f"  {name}: {val}")
    return 0


def _generate_secret_value(name):
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
        if (any(c.isupper() for c in new_val) and any(c.islower() for c in new_val)
                and any(c.isdigit() for c in new_val) and any(c in '!@%^&*' for c in new_val)):
            return new_val


def _drop_stale_secret_fallbacks(name):
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


def _secrets_rotate(args):
    from vnc_remote_secure.core.config import (
        _system_env_path,
        set_env_persistent,
    )

    if not args.secret_name:
        print(f"Error: --name required. Available: {', '.join(sorted(_ROTATABLE))}")
        return 1
    name = args.secret_name.upper()
    if name not in _ROTATABLE:
        print(f"Error: cannot rotate '{name}'. Rotatable: {', '.join(sorted(_ROTATABLE))}")
        return 1

    new_val = _generate_secret_value(name)

    # Persist the rotation into the project .env — setting only
    # os.environ would lose the new value when this process exits, and
    # printing it would leak it into scrollback. The running services
    # pick it up on the next restart.
    if not set_env_persistent(name, new_val):
        print("Error: could not write .env", file=sys.stderr)
        return 1
    # set_env_persistent writes to whichever file holds the key (system
    # config.env for installed deployments, else .env) — report the real
    # target, not unconditionally the project .env.
    sys_env = _system_env_path()
    env_path = sys_env if (
        sys_env and os.path.isfile(sys_env)
        and any(
            ln.split('=', 1)[0].strip() == name and not ln.strip().startswith('#')
            for ln in Path(sys_env).read_text(encoding='utf-8').splitlines()
            if '=' in ln)
    ) else os.path.join(_find_project_root(), '.env')

    _drop_stale_secret_fallbacks(name)

    # Rotating the operator UI credential must kill every live operator
    # session — otherwise a logged-in session keeps working on the OLD
    # password's authority after the credential changed. Bumping the
    # epoch invalidates all sessions issued so far (services pick it up
    # via shared state without a restart).
    if name in ('USER_UI_PASSWORD', 'TTYD_PASSWD'):
        try:
            from vnc_remote_secure.security.sessions import (
                bump_operator_epoch)
            bump_operator_epoch()
            print("  All operator sessions revoked (credential changed)")
        except Exception:  # noqa: BLE001 - rotation already succeeded
            pass

    fp = hashlib.sha256(new_val.encode()).hexdigest()[:8]
    print(f"Rotated {name} (written to {env_path}; restart services to apply)")
    print(f"  Fingerprint: {fp}")
    # Credential rotation is a sensitive admin action — audit it like
    # session create/revoke (name and fingerprint only, never the value).
    _audit_cli('secret_rotate', 'success', f'name={name} fp={fp}')
    return 0


def _secrets_rotate_signing(args):
    """Rotate the file-backed signing secret with a coexistence window.

    Unlike ``secrets rotate --name AUTH_SECRET`` (hard cutover), this
    keeps the old key verifiable for the retire window so in-flight
    sessions and share links do not die at once.
    """
    from vnc_remote_secure.security.authentication import (
        rotate_signing_secret)
    ok, err = rotate_signing_secret()
    if not ok:
        print(f"Error: {err}")
        return 1
    print("Signing secret rotated. The previous key stays valid for "
          "7 days (verify-only); new tokens sign with the new key.")
    _audit_cli('signing_key_rotate', 'success', 'window=7d')
    return 0


def _secrets_redact(args):
    if not args.secret_name:
        print("Error: --name required")
        return 1
    from vnc_remote_secure.security.redaction import redact_env
    print(f"{args.secret_name}: {redact_env(args.secret_name, show_fingerprint=True)}")
    return 0


def _secrets_recovery_codes(args):
    """Generate MFA recovery codes and store only their hashes.

    ``RECOVERY_CODES_HASHES`` is consumed by the auth gateway as a
    comma-separated SHA-256 list (single-use — a spent code is removed
    at login). Without this command there was no way to produce a
    valid value: the generators in ``security.mfa`` existed but were
    never wired up. Codes are printed ONCE — only hashes persist.
    """
    from vnc_remote_secure.core.config import set_env_persistent
    from vnc_remote_secure.security.mfa import (
        generate_recovery_codes, hash_recovery_code)

    codes = generate_recovery_codes(8)
    hashes = ','.join(hash_recovery_code(c) for c in codes)
    if not set_env_persistent('RECOVERY_CODES_HASHES', hashes):
        print("Error: could not write .env", file=sys.stderr)
        return 1
    print("Recovery codes — store these NOW, they are shown once "
          "(only hashes are persisted, each code is single-use):")
    for c in codes:
        print(f"  {c}")
    _audit_cli('recovery_codes_generate', 'success', 'count=8')
    return 0


def _secrets_check(args):
    # Validate TLS config and secret file permissions.
    findings = []
    try:
        from vnc_remote_secure.security.tls_validation import validate_tls_config
        findings.extend(validate_tls_config())
    except (ImportError, OSError, ValueError) as e:
        # Validation framework failure is critical, not a warning.
        findings.append({'severity': 'critical',
                         'message': f'TLS validation error: {e}'})
    try:
        from vnc_remote_secure.security.file_permissions import validate_secret_files
        findings.extend(validate_secret_files())
    except (ImportError, OSError) as e:
        findings.append({'severity': 'critical',
                         'message': f'File permission check error: {e}'})

    if getattr(args, 'fix', False):
        findings = _secrets_check_fix(findings)

    if args.json:
        print(json.dumps(findings, indent=2))
    elif not findings:
        print("All checks passed.")
    else:
        for f in findings:
            sev = f.get('severity', 'info').upper()
            msg = f.get('message', '')
            print(f"  [{sev}] {msg}")
    criticals = [f for f in findings if f.get('severity') == 'critical']
    return 1 if criticals else 0


def _secrets_check_fix(findings):
    """Apply permission fixes for findings that carry a file path."""
    from vnc_remote_secure.security.file_permissions import (
        fix_secret_file_permissions,
        validate_secret_files,
    )
    for f in findings:
        path = f.get('file')
        if not path:
            continue
        if fix_secret_file_permissions(path):
            print(f"  [FIXED] {path}")
        else:
            print(f"  [FAILED] {path}")
    # Re-validate after fixing so the report reflects reality.
    remaining = [f for f in findings if not f.get('file')]
    with contextlib.suppress(ImportError, OSError):
        remaining.extend(validate_secret_files())
    return remaining


def cmd_secrets(args):
    """Manage secrets (status, rotate, redact)."""
    from vnc_remote_secure.core.config import load_env_file

    load_env_file()

    handlers = {
        'status': _secrets_status,
        'rotate': _secrets_rotate,
        'rotate-signing': _secrets_rotate_signing,
        'redact': _secrets_redact,
        'recovery-codes': _secrets_recovery_codes,
        'check': _secrets_check,
    }
    handler = handlers.get(args.secrets_action)
    if handler is None:
        print(f"Unknown secrets action: {args.secrets_action}")
        return 1
    return handler(args)
