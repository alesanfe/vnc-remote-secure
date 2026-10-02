"""Operator account + passkey management handlers."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _MAX_BODY,
    _err,
    _ok,
    _read_typed_body,
    _uc_error_status,
    operator_to_api,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


_OPERATOR_PATCH_KEYS = {"role", "disabled", "password"}


def _operator_record(username: str):
    """Store record for *username* or None."""
    from vnc_remote_secure.security.operator_users import load_store

    return load_store().get(username)


def _get_operators(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, {"operators": [operator_to_api(u) for u in read_models.operators_index()]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /operators")
        _err(handler, "Operator listing failed", 500)


def _get_operator_detail(handler, query):
    username = handler._api_params["username"]
    from vnc_remote_secure.engine.application import read_models

    data = read_models.operator_detail(username)
    if data is None:
        _err(handler, "Operator not found", 404)
        return
    _ok(handler, {"operator": data})


def _get_operator_passkeys(handler, query):
    """Public passkey view: opaque ref (sha256 prefix of the
    credential id), name, timestamps — never the credential id or
    public key."""
    username = handler._api_params["username"]
    operator = getattr(handler, "_api_operator", None) or {}
    if _operator_record(username) is None:
        _err(handler, "Operator not found", 404)
        return
    from vnc_remote_secure.engine.application.passkeys import gate_manage, list_passkeys
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        gate_manage(operator.get("username", "?"), set(operator.get("permissions") or []), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"passkeys": list_passkeys(username)})


def _post_passkey_register_begin(handler, query):
    """POST …/passkeys/register/begin — WebAuthn options (self, step-up)."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.passkeys import begin_registration
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        options = begin_registration(operator.get("username", "?"), handler._api_params["username"])
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"options": options})


def _post_passkey_register_complete(handler, query):
    """POST …/passkeys/register/complete — verify + persist."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import PasskeyRegisterRequest

    body, error = _read_typed_body(handler, PasskeyRegisterRequest, limit=_MAX_BODY)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application.passkeys import complete_registration
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        complete_registration(
            operator.get("username", "?"),
            handler._api_params["username"],
            body.credential,
            body.name,
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"registered": True}, status=201)


def _patch_passkey(handler, query):
    """PATCH …/passkeys/{ref} — rename (owner or admin_users)."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import PasskeyRenameRequest

    body, error = _read_typed_body(handler, PasskeyRenameRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    name = body.name
    from vnc_remote_secure.engine.application.passkeys import rename_passkey
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        rename_passkey(
            operator.get("username", "?"),
            set(operator.get("permissions") or []),
            handler._api_params["username"],
            handler._api_params["credential_ref"],
            name,
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"renamed": True})


def _delete_passkey(handler, query):
    """DELETE …/passkeys/{ref} — revoke (last-auth-method guarded)."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application.passkeys import delete_passkey
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        delete_passkey(
            operator.get("username", "?"),
            set(operator.get("permissions") or []),
            handler._api_params["username"],
            handler._api_params["credential_ref"],
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"deleted": True})


def _post_operator_create(handler, query):
    """POST /api/v1/operators — strict schema; a misspelled flag must
    never silently produce a wider account."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import OperatorCreateRequest

    body, error = _read_typed_body(handler, OperatorCreateRequest)
    if error:
        _err(handler, *error)
        return
    username = body.username
    password = body.password
    role = body.role
    enabled = body.enabled
    from vnc_remote_secure.core.validation import ValidationError, validate_password

    try:
        validate_password(password)
    except ValidationError as exc:
        _err(handler, str(exc), 400)
        return
    from vnc_remote_secure.engine.application.operators import create_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        rec = create_operator(
            operator.get("username", "?"),
            set(operator.get("permissions") or []),
            username,
            password,
            role,
            enabled,
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(
        handler,
        {
            "operator": operator_to_api({"username": username, **rec}),
        },
        status=201,
    )


def _patch_operator(handler, query):
    """PATCH /api/v1/operators/{username} — role, disabled, password.
    Internal fields (hash, timestamps) are never settable."""
    operator = handler._api_operator
    username = handler._api_params["username"]
    from vnc_remote_secure.backend.schemas import OperatorUpdateRequest

    body, error = _read_typed_body(handler, OperatorUpdateRequest)
    if error:
        _err(handler, *error)
        return
    if not body.model_fields_set:
        _err(handler, f"Allowed fields: {sorted(_OPERATOR_PATCH_KEYS)}", 400)
        return
    if _operator_record(username) is None:
        _err(handler, "Operator not found", 404)
        return
    from vnc_remote_secure.engine.application.operators import update_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    kw = {}
    if body.role is not None:
        kw["role"] = body.role
    if body.disabled is not None:
        kw["disabled"] = body.disabled
    if body.password is not None:
        from vnc_remote_secure.core.validation import (
            ValidationError,
            validate_password,
        )

        try:
            validate_password(body.password)
        except ValidationError as exc:
            _err(handler, str(exc), 400)
            return
        kw["password"] = body.password
    try:
        result = update_operator(
            operator.get("username", "?"), set(operator.get("permissions") or []), username, **kw
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(
        handler,
        {
            "operator": operator_to_api({"username": username, **result["record"]}),
            "changed": result["changed"],
            "sessions_revoked": result["sessions_revoked"],
        },
    )


def _delete_operator(handler, query):
    """DELETE /api/v1/operators/{username} — refuses the last viable
    administrator; live sessions die with the account."""
    operator = handler._api_operator
    username = handler._api_params["username"]
    from vnc_remote_secure.engine.application.operators import delete_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        delete_operator(operator.get("username", "?"), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"deleted": True})


def _post_operator_revoke_sessions(handler, query):
    """POST /api/v1/operators/{username}/sessions/revoke-all."""
    operator = handler._api_operator
    username = handler._api_params["username"]
    from vnc_remote_secure.engine.application.operators import revoke_sessions
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        revoke_sessions(operator.get("username", "?"), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"revoked": True})


def _get_operators_deleted(handler, query):
    """GET /api/v1/operators/deleted — tombstone restore candidates."""
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, {"deleted": read_models.deleted_operators()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /operators/deleted")
        _err(handler, "Deleted-operator listing failed", 500)


def _post_operator_restore(handler, query):
    """POST /api/v1/operators/{u}/restore — undo a deletion from its
    tombstone. The account returns disabled with a random password —
    an admin must set a password and re-enable it."""
    operator = handler._api_operator
    username = handler._api_params["username"]
    from vnc_remote_secure.engine.application.operators import restore_operator
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        rec = restore_operator(operator.get("username", "?"), username)
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, {"operator": operator_to_api({"username": username, **rec})})
