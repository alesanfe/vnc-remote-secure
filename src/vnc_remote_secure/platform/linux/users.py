"""Linux runtime user management.

Thin wrapper around :mod:`vnc_remote_secure.platform.linux.permissions`
providing the ``create_runtime_user``/``remove_runtime_user`` API
expected by the platform adapter contract.
"""
from vnc_remote_secure.platform.linux.permissions import (
    create_user,
    remove_user,
)


def create_runtime_user(username):
    """Create a system user for service isolation.

    The user is created as a system account (``-r``) with a nologin
    shell so it cannot be used for interactive logins.
    """
    # justification: useradd shell arg, not shell=True
    return create_user(username, system=True, shell='/usr/sbin/nologin')  # nosec B604


def remove_runtime_user(username):
    """Remove a runtime user and its home directory."""
    return remove_user(username)
