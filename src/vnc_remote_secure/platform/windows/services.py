"""Windows Services management via PowerShell."""
import subprocess

from vnc_remote_secure.core.exceptions import ServiceError


def _run_powershell(script):
    """Run a PowerShell command and return the CompletedProcess."""
    return subprocess.run(
        ['powershell', '-NoProfile', '-Command', script],
        capture_output=True, text=True,
    )


def install_service(name, binary, display_name=None, startup_type='Automatic'):
    """Install a Windows Service.

    Args:
        name: Service name.
        binary: Path to the service executable (with arguments if needed).
        display_name: Human-readable name. Defaults to ``name``.
        startup_type: One of ``Automatic``, ``Manual``, ``Disabled``.

    Returns:
        ``True`` on success.
    """
    display_name = display_name or name
    ps_script = (
        f"New-Service -Name '{name}' -BinaryPathName '{binary}' "
        f"-DisplayName '{display_name}' -StartupType {startup_type} "
        f"-ErrorAction SilentlyContinue"
    )
    result = _run_powershell(ps_script)
    if result.returncode != 0:
        raise ServiceError(f"Failed to install service {name}: {result.stderr.strip()}")
    return True


def start_service(name):
    """Start a Windows Service."""
    result = _run_powershell(f"Start-Service -Name '{name}' -ErrorAction SilentlyContinue")
    if result.returncode != 0:
        raise ServiceError(f"Failed to start {name}: {result.stderr.strip()}")
    return True


def stop_service(name):
    """Stop a Windows Service."""
    result = _run_powershell(
        f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue"
    )
    if result.returncode != 0:
        raise ServiceError(f"Failed to stop {name}: {result.stderr.strip()}")
    return True


def service_status(name):
    """Return a dict with ``running`` and ``enabled`` keys."""
    result = _run_powershell(
        f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status"
    )
    status = result.stdout.strip().lower()
    return {
        'running': status == 'running',
        'enabled': status in ('running', 'stopped'),
    }


def remove_service(name):
    """Stop and remove a Windows Service."""
    _run_powershell(f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue")
    result = _run_powershell(
        f"(Get-WmiObject Win32_Service -Filter \"Name='{name}'\").Delete()"
    )
    return result.returncode == 0
