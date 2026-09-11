"""systemd service management for Linux."""
import os
import subprocess

from vnc_remote_secure.core.exceptions import ServiceError


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
    if unit_content is not None:
        os.makedirs(os.path.dirname(unit_file), exist_ok=True)
        with open(unit_file, 'w', encoding='utf-8') as f:
            f.write(unit_content)
    elif not os.path.exists(unit_file):
        raise ServiceError(f"Unit file not found: {unit_file}")
    result = subprocess.run(
        ['systemctl', 'daemon-reload'],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def start_service(name):
    """Start a systemd service."""
    result = subprocess.run(
        ['systemctl', 'start', name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ServiceError(f"Failed to start {name}: {result.stderr.strip()}")
    return True


def stop_service(name):
    """Stop a systemd service."""
    result = subprocess.run(
        ['systemctl', 'stop', name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ServiceError(f"Failed to stop {name}: {result.stderr.strip()}")
    return True


def service_status(name):
    """Return a dict with ``running`` and ``enabled`` keys."""
    active = subprocess.run(
        ['systemctl', 'is-active', name],
        capture_output=True, text=True,
    )
    enabled = subprocess.run(
        ['systemctl', 'is-enabled', name],
        capture_output=True, text=True,
    )
    return {
        'running': active.stdout.strip() == 'active',
        'enabled': enabled.stdout.strip() == 'enabled',
    }


def remove_service(name):
    """Stop, disable, and remove a systemd service unit file."""
    subprocess.run(['systemctl', 'stop', name], capture_output=True)
    subprocess.run(['systemctl', 'disable', name], capture_output=True)
    unit_path = f'/etc/systemd/system/{name}.service'
    if os.path.exists(unit_path):
        os.remove(unit_path)
    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    return True
