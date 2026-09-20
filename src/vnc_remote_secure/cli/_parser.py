"""Argument parser construction for the CLI.

Internal to ``vnc_remote_secure.cli`` — not part of the public API.
"""
import argparse

from vnc_remote_secure.cli._common import (
    _add_common_args,
    _add_verbosity_args,
)
from vnc_remote_secure.cli.commands.config import cmd_config
from vnc_remote_secure.cli.commands.lifecycle import (
    cmd_install,
    cmd_restart,
    cmd_service,
    cmd_start,
    cmd_status,
    cmd_stop,
    cmd_uninstall,
)
from vnc_remote_secure.cli.commands.misc import cmd_help, cmd_version
from vnc_remote_secure.cli.commands.ops import (
    cmd_backup,
    cmd_doctor,
    cmd_restore,
    cmd_verify,
)
from vnc_remote_secure.cli.commands.secrets import cmd_secrets
from vnc_remote_secure.cli.commands.session import cmd_session


def _add_install_args(subparsers):
    """Create the ``install`` subparser."""
    p_install = subparsers.add_parser('install', help='Install and configure the system')
    _add_common_args(p_install)
    p_install.set_defaults(func=cmd_install)


def _add_start_args(subparsers):
    """Create the ``start`` subparser with its arguments."""
    p_start = subparsers.add_parser('start', help='Start all services')
    _add_common_args(p_start)
    p_start.add_argument('--no-ssl', action='store_true',
                         help='Start without SSL/TLS (HTTP only)')
    p_start.add_argument('--foreground', action='store_true',
                         help='Run in the foreground (used by the Windows '
                              'Service wrapper; blocks until interrupted)')
    p_start.set_defaults(func=cmd_start)


def _add_session_args(subparsers):
    """Create the ``session`` subparser with its sub-actions."""
    # Session (ephemeral remote sessions)
    p_session = subparsers.add_parser('session', help='Manage ephemeral remote sessions')
    # Common args on the PARENT too: wrappers (VncRemote.ps1) insert
    # --json/--verbose right after the subcommand name, before the
    # leaf action — argparse must accept them at both levels.
    _add_common_args(p_session)
    p_session_sub = p_session.add_subparsers(dest='session_action', required=True)
    p_create = p_session_sub.add_parser('create', help='Create a new ephemeral session')
    p_create.add_argument('--expires', default='30m', help='Duration (e.g. 30m, 2h, 1d)')
    p_create.add_argument('--role', default='viewer', choices=['viewer', 'support', 'operator', 'administrator'], help='Role (viewer, support, operator, administrator)')
    p_create.add_argument('--view-only', action='store_true',
                          help='View-only: blocks control channels (gamepad/terminal). '
                               'Caveat: RFB input on the VNC stream is not filtered')
    p_create.add_argument('--no-terminal', action='store_true', help='Disable terminal access')
    p_create.add_argument('--single-use', action='store_true', help='Session expires after first use')
    p_create.add_argument('--max-uses', type=int, default=0,
                          help='Maximum number of uses (0 = unlimited)')
    p_create.add_argument('--allowed-ip', help='Restrict to a specific IP')
    p_create.add_argument('--resource', default=None,
                          choices=['desktop', 'terminal', 'audio', 'gamepad'],
                          help='Bind the token to a single resource')
    _add_common_args(p_create, suppress_defaults=True)
    p_list = p_session_sub.add_parser('list', help='List active sessions')
    _add_common_args(p_list, suppress_defaults=True)
    p_revoke = p_session_sub.add_parser('revoke', help='Revoke a session')
    p_revoke.add_argument('token_pos', nargs='?', metavar='TOKEN',
                          help='Session token to revoke (positional)')
    p_revoke.add_argument('--token', default=None,
                          help='Session token to revoke')
    _add_common_args(p_revoke, suppress_defaults=True)
    p_session.set_defaults(func=cmd_session)


def _add_secrets_args(subparsers):
    """Create the ``secrets`` subparser with its sub-actions."""
    # Secrets (status, rotate, redact)
    p_secrets = subparsers.add_parser('secrets', help='Manage secrets (status, rotate, redact, check)')
    _add_common_args(p_secrets)
    p_secrets_sub = p_secrets.add_subparsers(dest='secrets_action', required=True)
    p_sstatus = p_secrets_sub.add_parser('status', help='Show secret status (no values)')
    _add_common_args(p_sstatus, suppress_defaults=True)
    p_srotate = p_secrets_sub.add_parser('rotate', help='Rotate a secret (generates new value)')
    p_srotate.add_argument('--name', dest='secret_name', required=True, help='Secret to rotate (TTYD_PASSWD, TEMP_USER_PASS, VNC_PASSWORD, HEALTH_AUTH_TOKEN, LANDING_PASSWORD, USER_UI_PASSWORD, AUTH_SECRET, FLASK_SECRET_KEY, BACKUP_PASSWORD)')
    _add_common_args(p_srotate, suppress_defaults=True)
    p_sredact = p_secrets_sub.add_parser('redact', help='Show redacted value of a secret')
    p_sredact.add_argument('--name', dest='secret_name', required=True, help='Secret name to redact')
    _add_common_args(p_sredact, suppress_defaults=True)
    p_scheck = p_secrets_sub.add_parser('check', help='Validate TLS config and secret file permissions')
    _add_common_args(p_scheck, suppress_defaults=True)
    p_scheck.add_argument(
        '--fix', action='store_true',
        help='Attempt to repair permissions on flagged secret files')
    p_secrets.set_defaults(func=cmd_secrets)


def _add_config_args(subparsers):
    """Create the ``config`` subparser with its sub-actions."""
    # Config
    p_config = subparsers.add_parser('config', help='Configuration management')
    _add_common_args(p_config)
    p_config_sub = p_config.add_subparsers(dest='config_action', required=True)
    p_ceff = p_config_sub.add_parser('show-effective', help='Show effective config with provenance')
    p_ceff.add_argument('--profile', help='Profile to evaluate (default: from .env)')
    _add_common_args(p_ceff, suppress_defaults=True)
    p_cval = p_config_sub.add_parser('validate', help='Validate config for contradictions')
    p_cval.add_argument('--profile', help='Profile to validate against')
    _add_common_args(p_cval, suppress_defaults=True)
    p_cdiff = p_config_sub.add_parser('diff', help='Diff two profiles')
    p_cdiff.add_argument('--profile-a', required=True, help='First profile')
    p_cdiff.add_argument('--profile-b', required=True, help='Second profile')
    _add_common_args(p_cdiff, suppress_defaults=True)
    p_cmig = p_config_sub.add_parser('migrate', help='Migrate config to current version format')
    _add_common_args(p_cmig, suppress_defaults=True)
    p_config.set_defaults(func=cmd_config)


def create_parser():
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='vnc-remote',
        description='VNC Remote Secure - Secure browser-based remote access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Install
    _add_install_args(subparsers)

    # Start
    _add_start_args(subparsers)

    # Stop
    p_stop = subparsers.add_parser('stop', help='Stop all services')
    _add_common_args(p_stop)
    p_stop.set_defaults(func=cmd_stop)

    # Restart
    p_restart = subparsers.add_parser('restart', help='Restart all services')
    _add_common_args(p_restart)
    p_restart.add_argument('--no-ssl', action='store_true',
                           help='Restart services without TLS (HTTP only)')
    p_restart.set_defaults(func=cmd_restart)

    # Status
    p_status = subparsers.add_parser('status', help='Check system status')
    _add_common_args(p_status)
    p_status.set_defaults(func=cmd_status)

    # Doctor
    p_doctor = subparsers.add_parser('doctor', help='Diagnose system readiness')
    _add_common_args(p_doctor)
    p_doctor.set_defaults(func=cmd_doctor)

    # Backup
    p_backup = subparsers.add_parser('backup', help='Create a backup')
    p_backup.add_argument('--list', action='store_true', help='List available backups')
    _add_common_args(p_backup)
    p_backup.set_defaults(func=cmd_backup)

    # Restore
    p_restore = subparsers.add_parser('restore', help='Restore from a backup')
    p_restore.add_argument('backup_file', nargs='?', help='Backup file path')
    _add_common_args(p_restore)
    p_restore.set_defaults(func=cmd_restore)

    # Uninstall
    p_uninstall = subparsers.add_parser('uninstall', help='Remove all project changes')
    p_uninstall.add_argument('--keep-data', action='store_true',
                             help='Keep SSL certs, data, and backups')
    _add_common_args(p_uninstall)
    p_uninstall.set_defaults(func=cmd_uninstall)

    # Service (systemd / Windows service mode)
    p_service = subparsers.add_parser('service', help='Run in service mode (systemd/Windows)')
    p_service.add_argument('--run', action='store_true',
                           help='Start all services in foreground (service mode)')
    _add_common_args(p_service)
    p_service.set_defaults(func=cmd_service)

    # Version
    p_version = subparsers.add_parser('version', help='Show version information')
    _add_common_args(p_version)
    p_version.set_defaults(func=cmd_version)

    # Session (ephemeral remote sessions)
    _add_session_args(subparsers)

    # Secrets (status, rotate, redact)
    _add_secrets_args(subparsers)

    # Config
    _add_config_args(subparsers)

    # Verify (audit chain / backup integrity)
    p_verify = subparsers.add_parser(
        'verify', help='Verify audit chain or backup integrity')
    _add_common_args(p_verify)
    p_verify_sub = p_verify.add_subparsers(dest='verify_action',
                                         required=True)
    p_vaudit = p_verify_sub.add_parser(
        'audit', help='Verify the hash-chained audit log')
    _add_common_args(p_vaudit, suppress_defaults=True)
    p_vbackup = p_verify_sub.add_parser(
        'backup', help='Verify a backup archive (decrypt + CRC)')
    p_vbackup.add_argument('backup_file', nargs='?',
                           help='Backup file (default: newest)')
    _add_common_args(p_vbackup, suppress_defaults=True)
    p_verify.set_defaults(func=cmd_verify)

    # Help
    p_help = subparsers.add_parser('help', help='Show this help message')
    _add_verbosity_args(p_help)
    p_help.set_defaults(func=cmd_help)

    return parser
