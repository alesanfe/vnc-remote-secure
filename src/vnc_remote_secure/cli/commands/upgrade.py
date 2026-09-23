"""``vnc-remote upgrade`` — self-upgrade with automatic rollback."""
import logging

logger = logging.getLogger(__name__)


def _upgrade_check(_args) -> int:
    from vnc_remote_secure.core.upgrader import upgrade_check
    info = upgrade_check()
    print(f"Installed version: {info['current']}")
    if info['available'] is None:
        print("No distribution channel reachable or package not "
              "published — use --from <wheel|url> to upgrade from a "
              "specific source.")
        return 0
    print(f"Available version: {info['available']} ({info['source']})")
    if info['update']:
        print(f"Update available: {info['current']} -> {info['update']}")
    else:
        print("Already up to date.")
    return 0


def _upgrade_run(args) -> int:
    from vnc_remote_secure.core.upgrader import (
        installed_version, perform_upgrade)
    source = getattr(args, 'source', None)
    if not getattr(args, 'yes', False):
        # Interactive confirmation — an upgrade rewrites the runtime
        # and touches the config backup path; never do it silently.
        try:
            answer = input(
                f"Upgrade {installed_version()} "
                f"({source or 'latest from PyPI'})? "
                "A pre-upgrade backup will be created. [y/N] ")
        except EOFError:
            answer = ''
        if answer.strip().lower() not in ('y', 'yes'):
            print("Aborted.")
            return 1

    result = perform_upgrade(source=source)
    if not result['ok']:
        print(f"Upgrade FAILED: {result.get('error', 'unknown error')}")
        if result.get('rolled_back'):
            print("Automatic rollback succeeded — previous state "
                  f"restored from {result.get('backup')}")
        else:
            print("Automatic rollback FAILED or unavailable — run "
                  "'vnc-remote upgrade --rollback' or "
                  "'vnc-remote restore <backup>' manually.")
        return 1
    print(f"Upgraded: {result['previous']} -> {result['version']}")
    print(f"Pre-upgrade backup: {result['backup']}")
    print("Restart services to run the new version: vnc-remote restart")
    return 0


def _upgrade_rollback(_args) -> int:
    from vnc_remote_secure.core.upgrader import perform_rollback
    result = perform_rollback()
    if not result['ok']:
        print(f"Rollback FAILED: {result.get('error', 'unknown error')}")
        return 1
    print(f"Rolled back — restored from {result['restored']}")
    print("Restart services: vnc-remote restart")
    return 0


def cmd_upgrade(args):
    """Upgrade/rollback command."""
    if getattr(args, 'check', False):
        return _upgrade_check(args)
    if getattr(args, 'rollback', False):
        return _upgrade_rollback(args)
    return _upgrade_run(args)
