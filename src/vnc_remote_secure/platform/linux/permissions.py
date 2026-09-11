"""POSIX permission and user management for Linux."""
import os
import shutil
import subprocess

from vnc_remote_secure.core.exceptions import PlatformError


def set_permissions(path, owner=None, mode=None):
    """Set ownership and/or mode on ``path``.

    Args:
        path: Filesystem path to modify.
        owner: ``user`` or ``user:group`` string. ``None`` skips chown.
        mode: Octal mode integer (e.g. ``0o640``). ``None`` skips chmod.

    Returns:
        ``True`` on success.
    """
    if not os.path.exists(path):
        raise PlatformError(f"Path does not exist: {path}")
    if mode is not None:
        os.chmod(path, mode)
    if owner:
        if ':' in owner:
            user, group = owner.split(':', 1)
            shutil.chown(path, user, group)
        else:
            shutil.chown(path, owner)
    return True


def create_user(username, system=True, shell='/usr/sbin/nologin'):
    """Create a Linux system user.

    Returns ``True`` if the user was created or already exists.
    """
    if user_exists(username):
        return True
    cmd = ['useradd']
    if system:
        cmd.append('-r')
    cmd.extend(['-s', shell, username])
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def remove_user(username):
    """Remove a Linux user and its home directory."""
    result = subprocess.run(
        ['userdel', '-r', username],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def user_exists(username):
    """Return ``True`` if ``username`` exists on the system."""
    try:
        import pwd
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False
