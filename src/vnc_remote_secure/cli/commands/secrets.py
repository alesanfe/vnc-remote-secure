"""``secrets`` command: status, rotate, redact, check.

Thin CLI shell — the actual logic lives in
``security/secret_rotation.py`` so ``/api/v1/secrets/*`` behaves
identically.
"""
import json
import sys

from vnc_remote_secure.cli._common import _audit_cli


def _secrets_status(args):
    from vnc_remote_secure.security.secret_rotation import secret_status
    status = secret_status()
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print("Secret status:")
        for name, val in status.items():
            print(f"  {name}: {val}")
    return 0


def _secrets_rotate(args):
    from vnc_remote_secure.security.secret_rotation import (
        ROTATABLE,
        rotate_secret,
    )

    if not args.secret_name:
        print(f"Error: --name required. Available: {', '.join(sorted(ROTATABLE))}")
        return 1
    try:
        result = rotate_secret(args.secret_name)
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if result['sessions_revoked']:
        print("  All operator sessions revoked (credential changed)")
    print(f"Rotated {result['name']} "
          f"(written to {result['env_path']}; restart services to apply)")
    print(f"  Fingerprint: {result['fingerprint']}")
    # Credential rotation is a sensitive admin action — audit it like
    # session create/revoke (name and fingerprint only, never the value).
    _audit_cli('secret_rotate', 'success',
               f"name={result['name']} fp={result['fingerprint']}")
    return 0


def _secrets_rotate_signing(args):
    """Rotate the file-backed signing secret with a coexistence window.

    Unlike ``secrets rotate --name AUTH_SECRET`` (hard cutover), this
    keeps the old key verifiable for the retire window so in-flight
    sessions and share links do not die at once.
    """
    from vnc_remote_secure.security.secret_rotation import rotate_signing_key
    try:
        rotate_signing_key()
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1
    print("Signing secret rotated. The previous key stays valid for "
          "7 days (verify-only); new tokens sign with the new key.")
    _audit_cli('signing_key_rotate', 'success', 'window=7d')
    return 0


def _secrets_redact(args):
    if not args.secret_name:
        print("Error: --name required")
        return 1
    from vnc_remote_secure.security.secret_rotation import redact_secret
    print(f"{args.secret_name}: {redact_secret(args.secret_name)}")
    return 0


def _secrets_recovery_codes(args):
    """Generate MFA recovery codes and store only their hashes.

    Codes are printed ONCE — only hashes persist (each code is
    single-use at login).
    """
    from vnc_remote_secure.security.secret_rotation import (
        generate_recovery_codes,
    )
    try:
        codes = generate_recovery_codes(8)
    except OSError as e:
        print(f"Error: {e}")
        return 1
    print("Recovery codes — store these NOW, they are shown once "
          "(only hashes are persisted, each code is single-use):")
    for c in codes:
        print(f"  {c}")
    _audit_cli('recovery_codes_generate', 'success', 'count=8')
    return 0


def _secrets_check(args):
    # Validate TLS config and secret file permissions.
    from vnc_remote_secure.security.secret_rotation import secrets_check
    result = secrets_check(fix=getattr(args, 'fix', False))

    findings = result['remaining'] if isinstance(result, dict) else result
    if isinstance(result, dict):
        for f in result.get('fixed', []):
            tag = 'FIXED' if f['fixed'] else 'FAILED'
            print(f"  [{tag}] {f['file']}")

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
