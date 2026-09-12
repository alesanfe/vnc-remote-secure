"""Linux installer for VNC Remote Secure.

Copies project files into the standard system directories, installs
systemd unit files, creates runtime directories, and configures the
service user. Requires root privileges.
"""
import os
import shutil
import subprocess
import logging

from vnc_remote_secure.core.paths import (
    ensure_dirs,
    get_config_dir,
    get_data_dir,
    get_log_dir,
)
from vnc_remote_secure.platform.linux.services import install_service
from vnc_remote_secure.platform.linux.users import create_runtime_user


def install(project_root=None, service_user='vnc-remote'):
    """Perform a full Linux installation.

    Args:
        project_root: Path to the project source tree. When ``None`` the
            detected project root is used.
        service_user: System user to create for service isolation.

    Returns:
        ``True`` if the installation completed successfully.
    """
    if os.geteuid() != 0:
        raise PermissionError("Linux install requires root privileges")
    if project_root is None:
        from vnc_remote_secure.core.paths import find_project_root
        project_root = find_project_root()

    # 1. Create standard directories.
    ensure_dirs()

    # 2. Copy configuration files.
    config_src = os.path.join(project_root, 'src', 'config')
    if os.path.isdir(config_src):
        for filename in os.listdir(config_src):
            src = os.path.join(config_src, filename)
            dst = os.path.join(get_config_dir(), filename)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

    # 3. Create the runtime service user.
    create_runtime_user(service_user)

    # 4. Install systemd unit files (placeholder definitions).
    unit_file = os.path.join(get_config_dir(), 'vnc-remote.service')
    install_service('vnc-remote', unit_file)

    # 5. Set ownership on data/log directories.
    logger = logging.getLogger(__name__)
    for path in (get_data_dir(), get_log_dir()):
        try:
            shutil.chown(path, service_user, service_user)
        except (LookupError, OSError) as exc:
            logger.warning("Failed to chown %s to %s: %s", path, service_user, exc)

    return True


def uninstall(service_user='vnc-remote'):
    """Remove installed files, services, and the runtime user."""
    from vnc_remote_secure.platform.linux.services import remove_service
    from vnc_remote_secure.platform.linux.users import remove_runtime_user
    remove_service('vnc-remote')
    remove_runtime_user(service_user)
    for path in (get_config_dir(), get_data_dir(), get_log_dir()):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    return True
