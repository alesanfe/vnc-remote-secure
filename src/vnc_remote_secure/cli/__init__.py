"""VNC Remote Secure - Unified cross-platform CLI.

This is the single canonical entry point for all platforms. The
Python service manager (``core.service_manager``) owns the lifecycle
of all services. Platform-specific operations (install, firewall,
service registration) are delegated to the platform adapter
(``platform/{linux,windows}/``), not to Bash or PowerShell scripts.

Layout::

    cli/
    ├── _app.py        — main() entry point
    ├── _parser.py     — create_parser() and subcommand builders
    ├── _common.py     — shared helpers (audit, project root, argparse)
    └── commands/      — one module per command domain

Usage:
    vnc-remote <command> [options]

Commands:
    install     Install and configure the system
    start       Start all services
    stop        Stop all services
    restart     Restart all services
    status      Check system status
    doctor      Diagnose system readiness
    session     Manage ephemeral remote sessions
    secrets     Manage secrets (status, rotate, redact, check)
    config      Configuration management (show-effective, validate, diff, migrate)
    backup      Create a backup
    restore     Restore from a backup
    uninstall   Remove all project changes
    service     Run in service mode (foreground, for systemd/Windows Services)
    version     Show version information
    help        Show this help message
"""
# Re-export the public surface so ``vnc_remote_secure.cli:main`` (the
# declared project script) and ``python -m vnc_remote_secure.cli``
# keep working after the cli.py -> cli/ package refactor.
from vnc_remote_secure.cli._app import main
from vnc_remote_secure.cli._parser import create_parser

# Command handlers are re-exported for backwards compatibility with
# callers/tests that imported ``vnc_remote_secure.cli.cmd_*``.
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

__all__ = [
    'main',
    'create_parser',
    'cmd_install', 'cmd_start', 'cmd_stop', 'cmd_restart',
    'cmd_status', 'cmd_doctor', 'cmd_backup', 'cmd_restore',
    'cmd_uninstall', 'cmd_service', 'cmd_version', 'cmd_session',
    'cmd_secrets', 'cmd_config', 'cmd_verify', 'cmd_help',
]
