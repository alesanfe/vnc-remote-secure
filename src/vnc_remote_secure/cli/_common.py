"""Shared helpers for the CLI subcommands.

Internal to ``vnc_remote_secure.cli`` — not part of the public API.
"""
import argparse
import os
import platform


def _find_project_root():
    """Find project root directory (delegates to the canonical helper)."""
    from vnc_remote_secure.core.paths import find_project_root
    return find_project_root()


def _audit_cli(event: str, result: str, detail: str = ''):
    """Record a sensitive CLI action in the audit log (best-effort).

    Session create/revoke, secret rotation, backup/restore and
    uninstall are operator actions that must leave a trace like the
    web-side events do. Never raises — a broken audit log must not
    break the CLI.
    """
    try:
        from vnc_remote_secure.security.audit import audit_log
        audit_log(
            event,
            user=os.environ.get('USERNAME')
                 or os.environ.get('USER', 'admin'),
            result=result,
            detail=detail,
        )
    except Exception:  # noqa: BLE001
        pass


def _is_windows():
    """Check if running on Windows."""
    return platform.system() == 'Windows'


def _add_common_args(parser, suppress_defaults=False):
    """Add common arguments (--dry-run, --json, --verbose, --quiet) to a subparser.

    ``suppress_defaults=True`` is required on SECOND-level subparsers
    (``session list``, ``secrets check``…): argparse parses leaf
    subcommands into a fresh namespace and copies every attribute back,
    so a leaf ``--json`` with a plain ``False`` default would silently
    clobber a flag the caller placed on the PARENT
    (``vnc-remote session --json list`` — the order the PowerShell
    wrapper emits). ``argparse.SUPPRESS`` keeps the leaf from creating
    the attribute unless the flag was actually given, preserving the
    parent's value.
    """
    kw = {'default': argparse.SUPPRESS} if suppress_defaults else {}
    parser.add_argument('--dry-run', action='store_true',
                        help='Simulate without making changes', **kw)
    parser.add_argument('--json', action='store_true',
                        help='JSON output (status, doctor)', **kw)
    _add_verbosity_args(parser, suppress_defaults=suppress_defaults)


def _add_verbosity_args(parser, suppress_defaults=False):
    """Add --verbose/--quiet to a subparser.

    Applied to every top-level command so the flags are uniformly
    accepted — main() wires them to the logging level.
    """
    kw = {'default': argparse.SUPPRESS} if suppress_defaults else {}
    parser.add_argument('--verbose', action='store_true', help='Verbose output', **kw)
    parser.add_argument('--quiet', action='store_true', help='Quiet output', **kw)
