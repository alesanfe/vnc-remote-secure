"""Windows ACL and user management via PowerShell."""
import os
import subprocess

from vnc_remote_secure.core.exceptions import PlatformError


def _run_powershell(script):
    """Run a PowerShell command and return the CompletedProcess."""
    return subprocess.run(
        ['powershell', '-NoProfile', '-Command', script],
        capture_output=True, text=True,
    )


def set_permissions(path, owner=None, mode=None):
    """Set ACL permissions on ``path`` using icacls.

    Args:
        path: Filesystem path to modify.
        owner: User or group to grant full control. ``None`` skips.
        mode: Ignored on Windows (POSIX concept); accepted for API
            compatibility with the Linux counterpart.

    Returns:
        ``True`` on success.
    """
    if not os.path.exists(path):
        raise PlatformError(f"Path does not exist: {path}")
    if owner is None:
        return True
    result = subprocess.run(
        ['icacls', path, '/grant', f'{owner}:(OI)(CI)F', '/T'],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def create_user(username, password=None):
    """Create a local Windows user.

    Returns ``True`` if the user was created or already exists.
    """
    if user_exists(username):
        return True
    if password is None:
        # Create with a random password; user cannot log in interactively.
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(32))
    ps_script = (
        f"New-LocalUser -Name '{username}' "
        f"-Password (ConvertTo-SecureString '{password}' -AsPlainText -Force) "
        f"-Description 'VNC Remote Secure runtime user' -ErrorAction SilentlyContinue"
    )
    result = _run_powershell(ps_script)
    return result.returncode == 0


def remove_user(username):
    """Remove a local Windows user."""
    ps_script = f"Remove-LocalUser -Name '{username}' -ErrorAction SilentlyContinue"
    result = _run_powershell(ps_script)
    return result.returncode == 0


def user_exists(username):
    """Return ``True`` if ``username`` exists as a local user."""
    ps_script = (
        f"if (Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue) "
        f"{{ 'yes' }} else {{ 'no' }}"
    )
    result = _run_powershell(ps_script)
    return result.stdout.strip().lower() == 'yes'
