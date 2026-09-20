"""systemd service management for Linux."""
import os
import re

from vnc_remote_secure.core.exceptions import ServiceError
from vnc_remote_secure.core.processes import run_cmd

# systemd unit names: alphanumerics, '-', '_', '@', '.', ':', '\'.
# Anything else (notably '/' or '..') would escape the unit dir when
# building the file path.
_UNIT_NAME_RE = re.compile(r'^[A-Za-z0-9_.:@\\-]+$')


def _check_unit_name(name):
    """Reject unit names that would escape /etc/systemd/system."""
    if not name or '/' in name or '..' in name \
            or not _UNIT_NAME_RE.match(name):
        raise ServiceError(f"Invalid systemd unit name: {name!r}")


def install_service(name, unit_file, unit_content=None):
    """Install a systemd unit file and reload the daemon.

    Args:
        name: Service name (without ``.service`` suffix).
        unit_file: Path to write the unit file. If ``unit_content`` is
            ``None`` and ``unit_file`` already exists it is left as-is.
        unit_content: Optional unit file body to write.

    Returns:
        ``True`` on success.
    """
    _check_unit_name(name)
    if unit_content is not None:
        os.makedirs(os.path.dirname(unit_file), exist_ok=True)
        with open(unit_file, 'w', encoding='utf-8') as f:
            f.write(unit_content)
    elif not os.path.exists(unit_file):
        raise ServiceError(f"Unit file not found: {unit_file}")
    result = run_cmd(
        ['systemctl', 'daemon-reload'],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def remove_service(name):
    """Stop, disable, and remove a systemd service unit file."""
    _check_unit_name(name)
    run_cmd(['systemctl', 'stop', name], capture_output=True)
    run_cmd(['systemctl', 'disable', name], capture_output=True)
    unit_path = f'/etc/systemd/system/{name}.service'
    if os.path.exists(unit_path):
        os.remove(unit_path)
    run_cmd(['systemctl', 'daemon-reload'], capture_output=True)
    return True
