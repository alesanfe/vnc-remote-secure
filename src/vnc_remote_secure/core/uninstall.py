"""Uninstaller for VNC Remote Secure.

The canonical Python uninstaller replaces the legacy
``scripts/maintenance/uninstall.sh`` Bash script. It stops all
services, removes systemd/Windows-service registrations, firewall
rules, the runtime user, and optionally SSL certificates and data.
"""
import logging
import os
import shutil
import subprocess

from vnc_remote_secure.core.paths import (
    get_config_dir,
    get_data_dir,
    get_log_dir,
    get_run_dir,
    get_ssl_dir,
)
from vnc_remote_secure.platform.base import get_adapter
from vnc_remote_secure.platform.detection import is_windows

logger = logging.getLogger(__name__)


def uninstall(keep_data: bool = False, force: bool = False) -> dict:
    """Uninstall VNC Remote Secure.

    Args:
        keep_data: When True, keep SSL certificates, data, and backups.
        force: When True, do not prompt for confirmation (non-interactive).

    Returns:
        A dict mapping step names to success booleans.
    """
    # Load the effective env first: TEMP_USER (and other operator
    # overrides) live in .env/config.env — without this the runtime
    # user created at install time would be left behind.
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    results = {}

    # 1. Stop all running services.
    try:
        from vnc_remote_secure.core.service_manager import stop_all
        stop_all()
        results['stop_services'] = True
    except Exception as e:
        logger.warning("Failed to stop services: %s", e)
        results['stop_services'] = False

    adapter = get_adapter()
    results.update(_remove_service_registration(adapter))
    results.update(_remove_firewall(adapter))
    results.update(_remove_runtime_users(adapter))
    if not is_windows():
        results.update(_remove_linux_artifacts(adapter))
    results.update(_remove_data(keep_data))
    results.update(_remove_binaries())

    logger.info("Uninstall complete (keep_data=%s)", keep_data)
    return results


def _remove_service_registration(adapter) -> dict:
    """Remove systemd/Windows-service registrations."""
    # The registered name differs per platform: 'vnc-remote' on
    # systemd, 'VncRemoteSecure' via sc.exe on Windows.
    service_name = 'VncRemoteSecure' if is_windows() else 'vnc-remote'
    try:
        adapter.remove_service(service_name)
        return {'remove_service': True}
    except Exception as e:
        logger.debug("Service removal failed: %s", e)
        return {'remove_service': False}


def _remove_firewall(adapter) -> dict:
    """Remove firewall rules matching the installer's prefixes."""
    # Use the prefix that matches the rules created by the installer
    # (VncRemoteSecure-{port}-tcp on Windows, vnc-remote on Linux UFW).
    try:
        if is_windows():
            adapter.remove_firewall_rule('VncRemoteSecure')
        else:
            adapter.remove_firewall_rule('vnc-remote')
        return {'remove_firewall': True}
    except Exception as e:
        logger.debug("Firewall rule removal failed: %s", e)
        return {'remove_firewall': False}


def _remove_runtime_users(adapter) -> dict:
    """Remove the operator-configured runtime user."""
    try:
        temp_user = os.environ.get('TEMP_USER', 'remote')
        adapter.remove_runtime_user(temp_user)
        return {'remove_user': True}
    except Exception as e:
        logger.debug("User removal failed: %s", e)
        return {'remove_user': False}


def _remove_linux_artifacts(adapter) -> dict:
    """Remove the 'vnc-remote' service user/group and nginx/fail2ban files.

    packaging/linux/install.sh creates the service user
    (useradd --system) plus the nginx site and fail2ban configs — the
    canonical uninstall must not orphan what the install creates.
    """
    results = {}
    try:
        adapter.remove_runtime_user('vnc-remote')
        results['remove_service_user'] = True
    except Exception as e:
        logger.debug("Service user removal failed: %s", e)
        results['remove_service_user'] = False
    # packaging/linux/install.sh also creates the 'vnc-remote' GROUP
    # (groupadd --system) — userdel does not remove it, so the
    # canonical uninstall must not orphan it either.
    try:
        from vnc_remote_secure.core.processes import run_cmd
        run_cmd(
            ['groupdel', 'vnc-remote'],
            capture_output=True, check=False, timeout=15)
        results['remove_service_group'] = True
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug("Service group removal failed: %s", e)
        results['remove_service_group'] = False
    for name, path in [
        ('nginx_enabled', '/etc/nginx/sites-enabled/vnc-remote-secure'),
        ('nginx_available', '/etc/nginx/sites-available/vnc-remote-secure'),
        ('fail2ban_jail', '/etc/fail2ban/jail.d/vnc-remote.local'),
        ('fail2ban_filter', '/etc/fail2ban/filter.d/vnc-remote.conf'),
    ]:
        try:
            if os.path.lexists(path):
                os.remove(path)
            results[f'remove_{name}'] = True
        except OSError as e:
            logger.warning("Could not remove %s: %s", path, e)
            results[f'remove_{name}'] = False
    return results


def _sweep_windows_localappdata(results: dict):
    """Sweep the per-user state dir on elevated Windows uninstalls."""
    # Elevated uninstall: get_*_dir() resolved to ProgramData, but
    # non-elevated dev runs wrote state to the per-user base
    # (%LOCALAPPDATA%\VncRemoteSecure, or LocalLow under MSIX-packaged
    # interpreters) — sweep both or generated credentials, pid state
    # and logs survive the uninstall on the operator's profile.
    try:
        from vnc_remote_secure.core.paths import _is_elevated_windows
        local = os.environ.get('LOCALAPPDATA', '')
        sweep = []
        if local:
            sweep.append(os.path.join(local, 'VncRemoteSecure'))
            sweep.append(os.path.join(
                os.path.dirname(local), 'LocalLow',
                'VncRemoteSecure'))
        if _is_elevated_windows():
            for local_base in sweep:
                if os.path.isdir(local_base):
                    shutil.rmtree(local_base)
            results['remove_localappdata'] = True
    except (OSError, shutil.Error) as e:
        logger.warning("Could not remove LOCALAPPDATA dir: %s", e)
        results['remove_localappdata'] = False


def _remove_data(keep_data: bool) -> dict:
    """Remove config/data/logs/run/ssl dirs unless ``keep_data``."""
    results = {}
    if keep_data:
        for name in ('config', 'data', 'logs', 'run', 'ssl'):
            results[f'remove_{name}'] = True  # skipped
        return results
    for name, path in [('config', get_config_dir()),
                       ('data', get_data_dir()),
                       ('logs', get_log_dir()),
                       ('run', get_run_dir()),
                       ('ssl', get_ssl_dir())]:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            results[f'remove_{name}'] = True
        except (OSError, shutil.Error) as e:
            logger.warning("Could not remove %s: %s", path, e)
            results[f'remove_{name}'] = False
    # Windows: the installer also writes the seeded ``config.env``
    # under the ProgramData root — outside the standard subdirs. It may
    # contain secrets, so it is user data (keep_data keeps it).
    if is_windows():
        path = os.path.join(os.path.dirname(get_config_dir()), 'config.env')
        try:
            if os.path.isfile(path):
                os.remove(path)
            results['remove_config.env'] = True
        except OSError as e:
            logger.warning("Could not remove %s: %s", path, e)
            results['remove_config.env'] = False
        _sweep_windows_localappdata(results)
    return results


def _remove_binaries() -> dict:
    """Remove installed binaries regardless of keep_data (not user data).

    packaging/linux/install.sh copies the package to
    /opt/vnc-remote-secure and the CLI wrapper to
    /usr/local/bin/vnc-remote; the Windows installer writes the package
    copy (``src/``) and the ``service-run.py`` launcher under the
    ProgramData root.
    """
    results = {}
    if is_windows():
        base = os.path.dirname(get_config_dir())
        targets = [(name, os.path.join(base, name))
                   for name in ('src', 'service-run.py')]
    else:
        targets = [('opt', '/opt/vnc-remote-secure'),
                   ('cli', '/usr/local/bin/vnc-remote')]
    for name, path in targets:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)
            results[f'remove_{name}'] = True
        except (OSError, shutil.Error) as e:
            logger.warning("Could not remove %s: %s", path, e)
            results[f'remove_{name}'] = False
    return results
