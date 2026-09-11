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
    backup      Create a backup
    restore     Restore from a backup
    uninstall   Remove all project changes
    version     Show version information
    help        Show this help message
"""
import argparse
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
        return _run_bash_script(project_root, 'src/rpi-vnc-remote.sh', ['install'])


def cmd_start(args):
    """Start all services."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would start all services")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Start'])
    else:
        return _run_bash_script(project_root, 'launch.sh')


def cmd_stop(args):
    """Stop all services."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would stop all services")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Stop'])
    else:
        kill_script = os.path.join(project_root, 'kill_all.sh')
        if os.path.exists(kill_script):
            return _run_bash_script(project_root, 'kill_all.sh')
        print("No stop script found", file=sys.stderr)
        return 1


def cmd_restart(args):
    """Restart all services."""
    project_root = _find_project_root()
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
            bash_args = ['status']
            if args.json:
                bash_args.append('--json')
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
            bash_args = ['doctor']
            if args.json:
                bash_args.append('--json')
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
        return _run_bash_script(project_root, 'scripts/backup.sh')


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
        return _run_bash_script(project_root, 'scripts/restore.sh', [args.backup_file])


def cmd_uninstall(args):
    """Remove all project changes."""
    project_root = _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would uninstall (stop services, remove firewall rules, configs)")
        return 0

    if _is_windows():
        return _run_powershell(project_root, 'VncRemote.ps1', ['Uninstall'])
    else:
        return _run_bash_script(project_root, 'scripts/uninstall.sh')


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
        print(f"VNC Remote Secure - Secure browser-based remote access")
        print(f"Platform: {info['platform']} {info['architecture']}")
        print(f"Python: {info['python']}")
    return 0


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

    # Version
    p_version = subparsers.add_parser('version', help='Show version information')
    p_version.add_argument('--json', action='store_true', help='JSON output')
    p_version.set_defaults(func=cmd_version)

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
