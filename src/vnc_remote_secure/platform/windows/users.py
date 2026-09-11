"""Windows runtime user management.

Thin wrapper around
:mod:`vnc_remote_secure.platform.windows.permissions` providing the
``create_runtime_user``/``remove_runtime_user``/``user_exists`` API
expected by the platform adapter contract.
"""
from vnc_remote_secure.platform.windows.permissions import (
    create_user,
    remove_user,
    user_exists,
)


def create_runtime_user(username):
    """Create a local Windows user for service isolation."""
    return create_user(username)


def remove_runtime_user(username):
    """Remove a runtime Windows user."""
    return remove_user(username)
