"""Windows installer for VNC Remote Secure.

Creates the ProgramData directory structure, configures Windows
Firewall rules for the service ports, and generates self-signed SSL
certificates when none are present.
"""
import logging
import os

from vnc_remote_secure.core.constants import (
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.core.paths import (
    ensure_dirs,
    get_config_dir,
    get_data_dir,
    get_log_dir,
    get_ssl_dir,
)
from vnc_remote_secure.platform.windows.firewall import configure_firewall
from vnc_remote_secure.security.certificates import generate_self_signed


def install(project_root=None, configure_firewall_rules=True):
    """Perform a full Windows installation.

    Args:
        project_root: Path to the project source tree (unused for file
            copy on Windows; ProgramData is the install target).
        configure_firewall_rules: Whether to open firewall ports.

    Returns:
        ``True`` if the installation completed successfully.
    """
    # 1. Create standard directories under ProgramData.
    ensure_dirs()

    # 2. Configure Windows Firewall for service ports.
    if configure_firewall_rules:
        for port in (DEFAULT_VNC_PORT, DEFAULT_NOVNC_PORT,
                     DEFAULT_TTYD_PORT, DEFAULT_HEALTH_PORT,
                     DEFAULT_LANDING_PORT):
            configure_firewall(port, 'tcp')

    # 3. Generate self-signed SSL certificate if none exists.
    cert_path = os.path.join(get_ssl_dir(), 'fullchain.pem')
    key_path = os.path.join(get_ssl_dir(), 'privkey.pem')
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        try:
            generate_self_signed(cert_path, key_path)
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Self-signed certificate generation failed: %s", exc
            )

    return True


def uninstall():
    """Remove installed directories and firewall rules."""
    import shutil

    from vnc_remote_secure.platform.windows.firewall import remove_firewall_rule
    for port in (DEFAULT_VNC_PORT, DEFAULT_NOVNC_PORT,
                 DEFAULT_TTYD_PORT, DEFAULT_HEALTH_PORT,
                 DEFAULT_LANDING_PORT):
        remove_firewall_rule(f'VncRemoteSecure-{port}-tcp')
    for path in (get_config_dir(), get_data_dir(), get_log_dir(), get_ssl_dir()):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    return True
