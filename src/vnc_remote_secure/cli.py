#!/usr/bin/env python3
"""
VNC Remote Secure - Unified cross-platform CLI.

This is the single entry point for all platforms.
Platform-specific operations are delegated to adapters:
- Linux: Bash scripts (src/lib/, native/linux/)
- Windows: PowerShell scripts (native/windows/)

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
    secrets     Manage secrets (status, rotate, redact)
    backup      Create a backup
    restore     Restore from a backup
    uninstall   Remove all project changes
    version     Show version information
    help        Show this help message
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys

# Package version
__version__ = "0.2.0"


def _find_project_root():
    """Find project root directory."""
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def _is_windows():
    """Check if running on Windows."""
    return platform.system() == 'Windows'


def _run_bash_script(project_root, script_path, args=None):
    """Run a Bash script (Linux/WSL or Git Bash on Windows)."""
    full_path = os.path.join(project_root, script_path)
    if not os.path.exists(full_path):
        print(f"Error: Script not found: {full_path}", file=sys.stderr)
        return 1

    if _is_windows():
        # Use Git Bash on Windows
        git_path = _find_git_bash()
        if git_path:
            cmd = [git_path, '-c', f"cd '{full_path.replace(os.sep, '/')}' && bash {os.path.basename(script_path)}"]
        else:
            print("Error: Git Bash not found", file=sys.stderr)
            return 1
    else:
        cmd = ['bash', full_path]

    if args:
        cmd.extend(args)

    result = subprocess.run(cmd, cwd=os.path.dirname(full_path))
    return result.returncode


def _find_git_bash():
    """Find bash.exe from Git for Windows."""
    import shutil
    git_exe = shutil.which('git')
    if git_exe:
        git_dir = os.path.dirname(git_exe)
        bash_exe = os.path.join(git_dir, 'bash.exe')
        if os.path.exists(bash_exe):
            return bash_exe
    return None


def _run_powershell(project_root, script_name, args=None):
    """Run a PowerShell script."""
    ps_script = os.path.join(project_root, 'native', 'windows', script_name)
    if not os.path.exists(ps_script):
        # Fallback to root-level script
        ps_script = os.path.join(project_root, script_name)
    if not os.path.exists(ps_script):
        print(f"Error: PowerShell script not found: {ps_script}", file=sys.stderr)
        return 1

    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps_script]
    if args:
        cmd.extend(args)

    result = subprocess.run(cmd)
    return result.returncode


def cmd_install(args):
    """Install and configure the system."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would perform installation:")
        print("  1. Check prerequisites")
        print("  2. Install dependencies")
        print("  3. Configure VNC server")
        print("  4. Generate SSL certificates")
        print("  5. Configure firewall")
        print("  6. Start all services")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Install'])
    else:
        return _run_bash_script(project_root, 'src/rpi-vnc-remote.sh', ['setup'])


def cmd_start(args):
    """Start all services."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would start all services")
        return 0

    if _is_windows():
        ps_args = ['Start']
        if getattr(args, 'no_ssl', False):
            ps_args.append('-NoSsl')
        return _run_powershell(project_root, 'VncRemote.ps1', ps_args)
    else:
        bash_args = ['start']
        if getattr(args, 'no_ssl', False):
            bash_args.append('--no-ssl')
        return _run_bash_script(project_root, 'src/rpi-vnc-remote.sh', bash_args)


def cmd_stop(args):
    """Stop all services."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would stop all services")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Stop'])
    else:
        rpi_script = os.path.join(project_root, 'src', 'rpi-vnc-remote.sh')
        if os.path.exists(rpi_script):
            return _run_bash_script(project_root, 'src/rpi-vnc-remote.sh', ['stop'])
        print("No stop script found", file=sys.stderr)
        return 1


def cmd_restart(args):
    """Restart all services."""
    _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would restart all services")
        return 0

    cmd_stop(args)
    import time
    time.sleep(2)
    return cmd_start(args)


def cmd_status(args):
    """Check system status."""
    project_root = _find_project_root()

    if _is_windows():
        ps_args = ['Get-Status']
        if args.json:
            ps_args.append('-Json')
        return _run_powershell(project_root, 'VncRemote.ps1', ps_args)
    else:
        cli_script = os.path.join(project_root, 'vnc-remote')
        if os.path.exists(cli_script):
            # Bash wrapper expects global flags before the subcommand.
            bash_args = []
            if args.json:
                bash_args.append('--json')
            bash_args.append('status')
            return _run_bash_script(project_root, 'vnc-remote', bash_args)
        print("CLI not found", file=sys.stderr)
        return 1


def cmd_doctor(args):
    """Diagnose system readiness."""
    project_root = _find_project_root()

    if _is_windows():
        ps_args = ['Test-Configuration']
        if args.json:
            ps_args.append('-Json')
        return _run_powershell(project_root, 'VncRemote.ps1', ps_args)
    else:
        cli_script = os.path.join(project_root, 'vnc-remote')
        if os.path.exists(cli_script):
            # Bash wrapper expects global flags before the subcommand.
            bash_args = []
            if args.json:
                bash_args.append('--json')
            bash_args.append('doctor')
            return _run_bash_script(project_root, 'vnc-remote', bash_args)
        print("CLI not found", file=sys.stderr)
        return 1


def cmd_backup(args):
    """Create a backup."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would create backup")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Backup'])
    else:
        return _run_bash_script(project_root, 'scripts/maintenance/backup.sh')


def cmd_restore(args):
    """Restore from a backup."""
    if not args.backup_file:
        print("Error: backup file required", file=sys.stderr)
        return 2

    project_root = _find_project_root()
    if args.dry_run:
        print(f"[DRY RUN] Would restore from {args.backup_file}")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Restore', args.backup_file])
    else:
        return _run_bash_script(project_root, 'scripts/maintenance/restore.sh', [args.backup_file])


def cmd_uninstall(args):
    """Remove all project changes."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would uninstall (stop services, remove firewall rules, configs)")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Uninstall'])
    else:
        return _run_bash_script(project_root, 'scripts/maintenance/uninstall.sh')


def cmd_service(args):
    """Run in Windows service mode (foreground)."""
    _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would run in service mode (foreground)")
        return 0

    if not getattr(args, 'run', False):
        print("Error: --run flag required for service mode", file=sys.stderr)
        return 1

    # Start all services and keep running until interrupted
    print("[SERVICE] Starting VNC Remote Secure in service mode...")
    rc = cmd_start(args)
    if rc != 0:
        print(f"[SERVICE] Failed to start services (exit code {rc})", file=sys.stderr)
        return rc

    print("[SERVICE] Services started. Running until interrupted (Ctrl+C)...")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SERVICE] Stopping services...")
        cmd_stop(args)
        return 0


def cmd_version(args):
    """Show version information."""
    info = {
        "version": __version__,
        "name": "VNC Remote Secure",
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
    }
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"vnc-remote {__version__}")
        print("VNC Remote Secure - Secure browser-based remote access")
        print(f"Platform: {info['platform']} {info['architecture']}")
        print(f"Python: {info['python']}")
    return 0


def cmd_session(args):
    """Manage ephemeral remote sessions."""
    from vnc_remote_secure.security.ephemeral_sessions import (
        ROLES,
        get_session_store,
    )

    store = get_session_store()

    if args.session_action == 'create':
        expires_in = _parse_duration(args.expires or '30m')
        role = args.role or 'viewer'
        if role not in ROLES:
            print(f"Error: unknown role '{role}'. Available: {', '.join(ROLES.keys())}")
            return 1

        session, signed_token = store.create(
            expires_in=expires_in,
            role=role,
            single_use=args.single_use,
            view_only=args.view_only,
            no_terminal=args.no_terminal,
            allowed_ip=args.allowed_ip,
            created_by=os.environ.get('USER', 'admin'),
        )

        # Build the access URL
        host = os.environ.get('DUCK_DOMAIN', 'localhost')
        https_port = os.environ.get('NGINX_HTTPS_PORT', '443')
        if https_port == '443':
            base_url = f"https://{host}"
        else:
            base_url = f"https://{host}:{https_port}"

        if args.json:
            print(json.dumps({
                'token': signed_token,
                'url': f"{base_url}/?session={signed_token}",
                'expires_in': expires_in,
                'role': role,
                'view_only': args.view_only,
                'no_terminal': args.no_terminal,
                'single_use': args.single_use,
            }, indent=2))
        else:
            print(f"Session created (role: {role}, expires in {expires_in}s)")
            print(f"URL: {base_url}/?session={signed_token}")
            if args.view_only:
                print("  View-only: yes")
            if args.no_terminal:
                print("  Terminal: disabled")
            if args.single_use:
                print("  Single-use: yes")
            if args.allowed_ip:
                print(f"  IP restriction: {args.allowed_ip}")
        return 0

    elif args.session_action == 'list':
        sessions = store.list_active()
        if args.json:
            print(json.dumps(sessions, indent=2))
        else:
            if not sessions:
                print("No active sessions.")
            else:
                print(f"Active sessions ({len(sessions)}):")
                for s in sessions:
                    print(f"  role={s['role']} expires={s['expires_at']} "
                          f"view_only={s['view_only']} single_use={s['single_use']}")
        return 0

    elif args.session_action == 'revoke':
        if not args.token:
            print("Error: --token required for revoke")
            return 1
        if store.revoke(args.token):
            print("Session revoked.")
            return 0
        else:
            print("Session not found.")
            return 1

    print(f"Unknown session action: {args.session_action}")
    return 1


def cmd_secrets(args):
    """Manage secrets (status, rotate, redact)."""
    import secrets as secrets_mod
    import string

    from vnc_remote_secure.core.config import load_env_file
    from vnc_remote_secure.security.redaction import get_secret_status, redact_env

    load_env_file()

    if args.secrets_action == 'status':
        status = get_secret_status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print("Secret status:")
            for name, val in status.items():
                print(f"  {name}: {val}")
        return 0

    elif args.secrets_action == 'rotate':
        if not args.secret_name:
            print("Error: --name required. Available: TTYD_PASSWD, TEMP_USER_PASS, VNC_PASSWORD")
            return 1

        name = args.secret_name.upper()
        rotatable = {'TTYD_PASSWD', 'TEMP_USER_PASS', 'VNC_PASSWORD', 'HEALTH_AUTH_TOKEN'}
        if name not in rotatable:
            print(f"Error: cannot rotate '{name}'. Rotatable: {', '.join(sorted(rotatable))}")
            return 1

        chars = string.ascii_letters + string.digits + '!@%^&*'
        while True:
            new_val = ''.join(secrets_mod.choice(chars) for _ in range(24))
            if (any(c.isupper() for c in new_val) and any(c.islower() for c in new_val)
                and any(c.isdigit() for c in new_val) and any(c in '!@%^&*' for c in new_val)):
                break

        os.environ[name] = new_val
        print(f"Rotated {name} (new value set in environment, update .env manually)")
        print(f"  Fingerprint: {hashlib.sha256(new_val.encode()).hexdigest()[:8]}")
        return 0

    elif args.secrets_action == 'redact':
        if not args.secret_name:
            print("Error: --name required")
            return 1
        print(f"{args.secret_name}: {redact_env(args.secret_name, show_fingerprint=True)}")
        return 0

    print(f"Unknown secrets action: {args.secrets_action}")
    return 1


def _parse_duration(s: str) -> int:
    """Parse a duration string like '30m', '2h', '1d' into seconds."""
    if not s:
        return 1800
    s = s.strip().lower()
    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    if s[-1] in units:
        try:
            return int(s[:-1]) * units[s[-1]]
        except ValueError:
            pass
    try:
        return int(s)
    except ValueError:
        return 1800


def cmd_help(args):
    """Show help message."""
    parser = create_parser()
    parser.print_help()
    return 0


def create_parser():
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='vnc-remote',
        description='VNC Remote Secure - Secure browser-based remote access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Common arguments for all subcommands
    common_args = [
        (['--dry-run'], {'action': 'store_true', 'help': 'Simulate without making changes'}),
        (['--json'], {'action': 'store_true', 'help': 'JSON output (status, doctor)'}),
        (['--verbose'], {'action': 'store_true', 'help': 'Verbose output'}),
        (['--quiet'], {'action': 'store_true', 'help': 'Quiet output'}),
    ]

    # Install
    p_install = subparsers.add_parser('install', help='Install and configure the system')
    for args_list, kwargs in common_args:
        p_install.add_argument(*args_list, **kwargs)
    p_install.set_defaults(func=cmd_install)

    # Start
    p_start = subparsers.add_parser('start', help='Start all services')
    for args_list, kwargs in common_args:
        p_start.add_argument(*args_list, **kwargs)
    p_start.add_argument('--no-ssl', action='store_true',
                         help='Start without SSL/TLS (HTTP only)')
    p_start.set_defaults(func=cmd_start)

    # Stop
    p_stop = subparsers.add_parser('stop', help='Stop all services')
    for args_list, kwargs in common_args:
        p_stop.add_argument(*args_list, **kwargs)
    p_stop.set_defaults(func=cmd_stop)

    # Restart
    p_restart = subparsers.add_parser('restart', help='Restart all services')
    for args_list, kwargs in common_args:
        p_restart.add_argument(*args_list, **kwargs)
    p_restart.set_defaults(func=cmd_restart)

    # Status
    p_status = subparsers.add_parser('status', help='Check system status')
    for args_list, kwargs in common_args:
        p_status.add_argument(*args_list, **kwargs)
    p_status.set_defaults(func=cmd_status)

    # Doctor
    p_doctor = subparsers.add_parser('doctor', help='Diagnose system readiness')
    for args_list, kwargs in common_args:
        p_doctor.add_argument(*args_list, **kwargs)
    p_doctor.set_defaults(func=cmd_doctor)

    # Backup
    p_backup = subparsers.add_parser('backup', help='Create a backup')
    for args_list, kwargs in common_args:
        p_backup.add_argument(*args_list, **kwargs)
    p_backup.set_defaults(func=cmd_backup)

    # Restore
    p_restore = subparsers.add_parser('restore', help='Restore from a backup')
    p_restore.add_argument('backup_file', nargs='?', help='Backup file path')
    for args_list, kwargs in common_args:
        p_restore.add_argument(*args_list, **kwargs)
    p_restore.set_defaults(func=cmd_restore)

    # Uninstall
    p_uninstall = subparsers.add_parser('uninstall', help='Remove all project changes')
    for args_list, kwargs in common_args:
        p_uninstall.add_argument(*args_list, **kwargs)
    p_uninstall.set_defaults(func=cmd_uninstall)

    # Service (Windows service mode)
    p_service = subparsers.add_parser('service', help='Run in Windows service mode')
    p_service.add_argument('--run', action='store_true',
                           help='Start all services in foreground (service mode)')
    for args_list, kwargs in common_args:
        p_service.add_argument(*args_list, **kwargs)
    p_service.set_defaults(func=cmd_service)

    # Version
    p_version = subparsers.add_parser('version', help='Show version information')
    p_version.add_argument('--json', action='store_true', help='JSON output')
    p_version.set_defaults(func=cmd_version)

    # Session (ephemeral remote sessions)
    p_session = subparsers.add_parser('session', help='Manage ephemeral remote sessions')
    p_session_sub = p_session.add_subparsers(dest='session_action')
    p_create = p_session_sub.add_parser('create', help='Create a new ephemeral session')
    p_create.add_argument('--expires', default='30m', help='Duration (e.g. 30m, 2h, 1d)')
    p_create.add_argument('--role', default='viewer', choices=['viewer', 'support', 'operator', 'administrator'], help='Role (viewer, support, operator, administrator)')
    p_create.add_argument('--view-only', action='store_true', help='View-only (no keyboard/mouse)')
    p_create.add_argument('--no-terminal', action='store_true', help='Disable terminal access')
    p_create.add_argument('--single-use', action='store_true', help='Session expires after first use')
    p_create.add_argument('--allowed-ip', help='Restrict to a specific IP')
    p_create.add_argument('--json', action='store_true', help='JSON output')
    p_list = p_session_sub.add_parser('list', help='List active sessions')
    p_list.add_argument('--json', action='store_true', help='JSON output')
    p_revoke = p_session_sub.add_parser('revoke', help='Revoke a session')
    p_revoke.add_argument('--token', required=True, help='Session token to revoke')
    p_session.set_defaults(func=cmd_session)

    # Secrets (status, rotate, redact)
    p_secrets = subparsers.add_parser('secrets', help='Manage secrets (status, rotate, redact)')
    p_secrets_sub = p_secrets.add_subparsers(dest='secrets_action')
    p_sstatus = p_secrets_sub.add_parser('status', help='Show secret status (no values)')
    p_sstatus.add_argument('--json', action='store_true', help='JSON output')
    p_srotate = p_secrets_sub.add_parser('rotate', help='Rotate a secret (generates new value)')
    p_srotate.add_argument('--name', required=True, help='Secret to rotate (e.g. TTYD_PASSWD)')
    p_sredact = p_secrets_sub.add_parser('redact', help='Show redacted value of a secret')
    p_sredact.add_argument('--name', required=True, help='Secret name to redact')
    p_secrets.set_defaults(func=cmd_secrets)

    # Help
    p_help = subparsers.add_parser('help', help='Show this help message')
    p_help.set_defaults(func=cmd_help)

    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
    except Exception as e:
        if hasattr(args, 'verbose') and args.verbose:
            raise
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
