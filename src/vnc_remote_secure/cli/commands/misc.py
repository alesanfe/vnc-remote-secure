"""Miscellaneous commands: version, help."""
import json
import platform


def cmd_version(args):
    """Show version information."""
    from vnc_remote_secure.core.constants import APP_NAME, APP_VERSION
    info = {
        "version": APP_VERSION,
        "name": APP_NAME,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
    }
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"vnc-remote {APP_VERSION}")
        print(f"{APP_NAME} - Secure browser-based remote access")
        print(f"Platform: {info['platform']} {info['architecture']}")
        print(f"Python: {info['python']}")
    return 0


def cmd_help(args):
    """Show help message."""
    # Deferred import: _parser imports this module for set_defaults,
    # so a top-level import would be circular.
    from vnc_remote_secure.cli._parser import create_parser
    parser = create_parser()
    parser.print_help()
    return 0
