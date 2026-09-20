"""POSIX permission and user management for Linux."""
import logging

from vnc_remote_secure.core.processes import run_cmd


def _valid_username(username):
    """Return True if ``username`` is safe to pass to useradd/userdel.

    The username lands as a positional argument — a value starting with
    ``-`` would be parsed as a flag (e.g. ``userdel -r -f``), so the
    adapter validates instead of trusting callers to have done so.
    """
    from vnc_remote_secure.core.validation import validate_username
    try:
        validate_username(username)
        return True
    except (ValueError, TypeError):
        logging.getLogger(__name__).warning(
            "Refusing invalid username %r", username)
        return False


def create_user(username, system=True, shell='/usr/sbin/nologin'):
    """Create a Linux system user.

    Returns ``True`` if the user was created or already exists.
    """
    if not _valid_username(username):
        return False
    if user_exists(username):
        return True
    cmd = ['useradd']
    if system:
        cmd.append('-r')
    cmd.extend(['-s', shell, '--', username])
    result = run_cmd(cmd, capture_output=True, text=True)
    return result.returncode == 0


def remove_user(username):
    """Remove a Linux user and its home directory.

    Refuses reserved/builtin names: the caller (TEMP_USER env) could
    otherwise pass e.g. ``root`` and ``userdel -r`` would attempt to
    delete a system account.
    """
    if not _valid_username(username):
        return False
    from vnc_remote_secure.core.constants import RESERVED_USERNAMES
    if username in RESERVED_USERNAMES:
        logging.getLogger(__name__).warning(
            "Refusing to remove reserved user %s", username)
        return False
    result = run_cmd(
        ['userdel', '-r', '--', username],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def set_user_password(username, password):
    """Set a user's login password via ``chpasswd``.

    Returns ``True`` on success. ``chpasswd`` consumes ``user:pass``
    lines, so credentials containing ``:`` or a newline would inject
    or corrupt records — reject them rather than mangle /etc/shadow.
    """
    if not _valid_username(username):
        return False
    if ':' in username or '\n' in username or '\r' in username:
        return False
    if '\n' in password or '\r' in password:
        return False
    result = run_cmd(
        ['chpasswd'],
        input=f'{username}:{password}\n',
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
