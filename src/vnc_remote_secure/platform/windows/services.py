"""Windows Service management for VNC Remote Secure.

Provides ``install_service`` and ``remove_service`` parity with the Linux
adapter so the canonical installer can register the application as a
Windows Service. The service executable is the Python CLI entry point
(``vnc-remote``), which delegates to ``vnc_remote_secure.cli:main``.

We use ``sc.exe`` (available on every supported Windows version) instead
of the ``New-Service`` PowerShell cmdlet so the helper works even on
systems without PowerShell 5+.
"""
import os
import subprocess

from vnc_remote_secure.core.exceptions import ServiceError

SERVICE_NAME = 'VncRemoteSecure'


def _resolve_service_binary():
    """Return the command line for the Windows Service executable.

    Prefers the ``service-run.py`` launcher installed into ProgramData
    by the installer — it puts the copied package on ``sys.path`` so the
    service does not need a pip install nor PYTHONPATH (sc.exe services
    cannot set environment variables). Falls back to ``python -m`` for
    pip-installed deployments.
    """
    import sys
    launcher = os.path.join(
        os.environ.get('ProgramData', r'C:\ProgramData'),
        'VncRemoteSecure', 'service-run.py')
    if os.path.isfile(launcher):
        return f'"{sys.executable}" "{launcher}" start --foreground'
    python = os.environ.get('PYTHON', 'python')
    # Quote the interpreter — a path containing spaces (e.g.
    # "C:\Program Files\Python311\python.exe") would split the
    # binPath into bogus arguments.
    if ' ' in python and not python.startswith('"'):
        python = f'"{python}"'
    return f'{python} -m vnc_remote_secure.cli start --foreground'


def install_service(name=SERVICE_NAME, unit_file=None, unit_content=None):
    """Install and start a Windows Service backed by the Python CLI.

    Args:
        name: Windows Service name. Defaults to ``VncRemoteSecure``.
        unit_file: Ignored on Windows (kept for API parity with Linux).
        unit_content: Ignored on Windows (kept for API parity with Linux).

    Returns:
        ``True`` on success.

    Raises:
        ServiceError: if ``sc.exe`` is unavailable or the service already
            exists and could not be removed first.
    """
    # Remove any pre-existing service with the same name so installs are
    # idempotent. ``sc query`` returns non-zero when the service is absent.
    query = subprocess.run(
        ['sc', 'query', name], capture_output=True, text=True,
    )
    if query.returncode == 0:
        remove_service(name)

    bin_path = _resolve_service_binary()
    create = subprocess.run(
        ['sc', 'create', name, 'binPath=', bin_path, 'start=', 'auto'],
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        raise ServiceError(
            f"Failed to create Windows Service '{name}': {create.stderr.strip()}"
        )
    # Set a human-readable display name and description.
    subprocess.run(
        ['sc', 'description', name,
         'VNC Remote Secure — secure browser-based remote access.'],
        capture_output=True, text=True,
    )
    return True


def remove_service(name=SERVICE_NAME):
    """Stop and remove a Windows Service.

    Returns ``True`` on success or when the service was not present.
    """
    subprocess.run(['sc', 'stop', name], capture_output=True, text=True)
    delete = subprocess.run(
        ['sc', 'delete', name], capture_output=True, text=True,
    )
    # ``sc delete`` returns 1072 when the service does not exist.
    return delete.returncode in (0, 1072)
