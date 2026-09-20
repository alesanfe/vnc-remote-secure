"""Operational commands: doctor, backup, restore."""
import json
import os
import sys

from vnc_remote_secure.cli._common import _audit_cli


def cmd_doctor(args):
    """Diagnose system readiness via the canonical Python doctor.

    Checks configuration consistency, blocking security findings,
    directory existence, secret strength, TLS certificates,
    dependencies, and service port bindings — all in Python, without
    delegating to Bash or PowerShell.
    """
    from vnc_remote_secure.core.doctor import format_doctor, run_doctor
    result = run_doctor(as_json=args.json)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_doctor(result))
    return 0 if result['healthy'] else 1


def cmd_backup(args):
    """Create a backup via the canonical Python backup module."""
    if args.dry_run:
        print("[DRY RUN] Would create backup")
        return 0

    if getattr(args, 'list', False):
        from vnc_remote_secure.core.backup import list_backups
        backups = list_backups()
        if not backups:
            print("No backups found.")
        else:
            print(f"Found {len(backups)} backup(s):")
            for b in backups:
                print(f"  {b}")
        return 0

    from vnc_remote_secure.core.backup import create_backup
    try:
        path = create_backup()
        print(f"Backup created: {path}")
        _audit_cli('backup_create', 'success', os.path.basename(path))
        return 0
    except Exception as e:
        print(f"Backup failed: {e}", file=sys.stderr)
        _audit_cli('backup_create', 'failure', str(e))
        return 1


def cmd_restore(args):
    """Restore from a backup via the canonical Python backup module."""
    if not args.backup_file:
        print("Error: backup file required", file=sys.stderr)
        print("Usage: vnc-remote restore <backup_file>", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"[DRY RUN] Would restore from {args.backup_file}")
        return 0

    from vnc_remote_secure.core.backup import restore_backup
    try:
        ok = restore_backup(args.backup_file)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"Restore failed: {e}", file=sys.stderr)
        return 1
    if not ok:
        print("Restore failed: see logs for details.", file=sys.stderr)
        _audit_cli('backup_restore', 'failure', args.backup_file)
        return 1
    print(f"Restored from: {args.backup_file}")
    _audit_cli('backup_restore', 'success', args.backup_file)
    return 0


def cmd_verify(args):
    """Verify audit-chain or backup integrity.

    ``verify audit`` replays the hash chain over the audit log —
    tamper-evidence, not tamper-proofing (an attacker with write
    access to the host can always rewrite the whole file; export logs
    externally for stronger guarantees).

    ``verify backup [FILE]`` decrypts (if needed) and CRC-checks every
    tar member. Without FILE it verifies the newest backup.
    """
    action = getattr(args, 'verify_action', None)

    if action == 'audit':
        from vnc_remote_secure.security.audit import verify_chain
        intact, message = verify_chain()
        if args.json:
            print(json.dumps({'intact': intact, 'message': message},
                             indent=2))
        else:
            print(f"Audit chain: {'INTACT' if intact else 'BROKEN'}"
                  f"{' — ' + message if message else ''}")
        return 0 if intact else 1

    if action == 'backup':
        from vnc_remote_secure.core.backup import (
            list_backups,
            verify_backup,
        )
        backup_file = getattr(args, 'backup_file', None)
        if not backup_file:
            backups = list_backups()
            if not backups:
                print("No backups found.")
                return 1
            backup_file = backups[0]
        ok, message, count = verify_backup(backup_file)
        if args.json:
            print(json.dumps({'file': backup_file, 'ok': ok,
                              'members': count, 'message': message},
                             indent=2))
        else:
            print(f"{backup_file}: {message}")
        return 0 if ok else 1

    print(f"Unknown verify action: {action}")
    return 1
