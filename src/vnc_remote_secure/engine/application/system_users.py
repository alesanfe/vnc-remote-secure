"""System (OS) user management use cases — migrated from the legacy
Flask ``web/routes/users.py`` surface.

Domain rules live here, not in the transport:

* reserved/builtin account names and the *current* process account
  can never be created or deleted;
* username/password policy is enforced before the OS is touched;
* every mutation emits an audit event with the actor;
* step-up is enforced by the route metadata (``step_up=True``) —
  same guarantee the legacy Flask routes applied.

Infrastructure (OS calls) goes through
``engine.infrastructure.stores`` — this module never imports
``platform.*`` or ``security.*`` directly.
"""
from __future__ import annotations

from vnc_remote_secure.engine.domain.decision import (
    ERR_INVALID,
    ERR_LAST_ADMIN,
    ERR_PERMISSION,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores


def _audit(event: str, actor: str, detail: str,
           result: str = '') -> None:
    stores.audit(event, actor, detail, result=result)


def list_system_users() -> list:
    """Non-reserved OS accounts — the public view (no shadow data)."""
    return stores.system_users_list()


def create_system_user(actor: str, username: str,
                       password: str) -> dict:
    """Create a runtime OS account. Reserved names and policy
    violations are refused *before* the platform adapter runs."""
    from vnc_remote_secure.core.validation import (
        sanitize_input,
        validate_password,
        validate_username,
    )
    username = sanitize_input(username)
    try:
        validate_username(username)
    except ValueError as exc:
        raise UseCaseError(ERR_INVALID, str(exc)) from exc
    if username in stores.system_usernames_reserved():
        _audit('api_permission_denied', actor,
               f'reserved system user create: {username}')
        raise UseCaseError(ERR_PERMISSION, 'Cannot create system users')
    try:
        validate_password(password, 'user_password')
    except ValueError as exc:
        raise UseCaseError(ERR_INVALID, str(exc)) from exc
    try:
        stores.system_user_create(username, password)
    except Exception as exc:  # noqa: BLE001 - adapter failures differ per OS
        _audit('user_create', actor, f'target={username}',
               result='failure')
        raise UseCaseError(ERR_INVALID, 'User creation failed') from exc
    _audit('user_create', actor, f'target={username}')
    return {'username': username}


def delete_system_user(actor: str, username: str) -> None:
    """Delete a runtime OS account. The current process account and
    reserved names are protected — killing either would break the
    running services."""
    from vnc_remote_secure.core.validation import (
        sanitize_input,
        validate_username,
    )
    username = sanitize_input(username)
    try:
        validate_username(username)
    except ValueError as exc:
        raise UseCaseError(ERR_INVALID, str(exc)) from exc
    if (username in stores.system_usernames_reserved()
            or username == stores.system_current_user()):
        _audit('api_permission_denied', actor,
               f'protected system user delete: {username}')
        raise UseCaseError(ERR_LAST_ADMIN, 'Cannot delete system users')
    try:
        deleted = stores.system_user_delete(username)
    except Exception as exc:  # noqa: BLE001
        _audit('user_delete', actor, f'target={username}',
               result='failure')
        raise UseCaseError(ERR_INVALID, 'User deletion failed') from exc
    if not deleted:
        _audit('user_delete', actor, f'target={username}',
               result='failure')
        raise UseCaseError(ERR_INVALID, 'User deletion failed')
    _audit('user_delete', actor, f'target={username}')
