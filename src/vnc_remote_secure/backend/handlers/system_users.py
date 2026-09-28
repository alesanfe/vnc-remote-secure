"""OS system-user management handlers."""
import logging

from vnc_remote_secure.backend.handlers.common import (
    _err,
    _ok,
    _read_typed_body,
    _uc_error_status,
)

logger = logging.getLogger(__name__)


def _get_system_users(handler, query):
    from vnc_remote_secure.engine.application.system_users import list_system_users
    _ok(handler, {'users': list_system_users()})


def _post_system_user_create(handler, query):
    """POST /api/v1/system-users — create a runtime OS account
    (admin_users + step-up)."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import SystemUserCreateRequest
    body, error = _read_typed_body(handler, SystemUserCreateRequest)
    if error:
        _err(handler, *error)
        return
    username = body.username
    password = body.password
    if not username.strip():
        _err(handler, 'username required', 400)
        return
    from vnc_remote_secure.engine.application.system_users import create_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        create_system_user(operator.get('username', '?'),
                           username, password)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'username': username.strip()}, status=201)


def _delete_system_user(handler, query):
    """DELETE /api/v1/system-users/{username} — admin_users + step-up;
    the current process account and reserved names are protected."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.system_users import delete_system_user
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    try:
        delete_system_user(operator.get('username', '?'),
                           handler._api_params['username'])
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {'deleted': True})
