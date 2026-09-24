"""Infrastructure adapters — the ONLY place engine code may touch
``security/*``.

Application use cases depend on these narrow accessors; when the
persistence layer moves (SQLite store, secret backend, remote audit
sink) only this module changes. Each function is intentionally thin —
a delegation, not a re-implementation.
"""
from __future__ import annotations

# --- Ephemeral share-link sessions -----------------------------------


def session_store():
    """The process/shared session store (create/get/revoke/list)."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    return get_session_store()


def revoke_ephemeral_token(token_id: str) -> bool:
    from vnc_remote_secure.security.ephemeral_sessions import revoke_session
    return revoke_session(token_id)


def mint_session_token(session, ttl_seconds: int) -> str:
    from vnc_remote_secure.security.ephemeral_sessions import create_ephemeral_token
    return create_ephemeral_token(session, ttl_seconds)


def session_refresh(store) -> None:
    """Re-read persisted sessions when the backend supports it —
    tests and future adapters may not need the hook."""
    fn = getattr(store, '_load_if_changed', None)
    if callable(fn):
        fn()


def session_roles() -> dict:
    """Role → default permission set for share links."""
    from vnc_remote_secure.security.ephemeral_sessions import ROLES
    return ROLES


def expand_session_permissions(perms: set) -> set:
    """Expand umbrella permissions (e.g. admin:* covers all)."""
    from vnc_remote_secure.security.ephemeral_sessions import expand_permissions
    return expand_permissions(perms)


# --- Operator accounts ------------------------------------------------


def operator_load_store() -> dict:
    from vnc_remote_secure.security.operator_users import load_store
    return load_store()


def operator_add(username: str, password: str, role: str) -> None:
    from vnc_remote_secure.security.operator_users import add_user
    return add_user(username, password, role)


def operator_set_disabled(username: str, disabled: bool) -> bool:
    from vnc_remote_secure.security.operator_users import set_disabled
    return set_disabled(username, disabled)


def operator_remove(username: str) -> bool:
    from vnc_remote_secure.security.operator_users import remove_user
    return remove_user(username)


def operator_roles() -> dict:
    from vnc_remote_secure.security.operator_users import ROLE_PERMISSIONS
    return ROLE_PERMISSIONS


def operator_set_password(username: str, password: str) -> bool:
    from vnc_remote_secure.security.operator_users import set_password
    return set_password(username, password)


def operator_set_role(username: str, role: str) -> bool:
    from vnc_remote_secure.security.operator_users import set_role
    return set_role(username, role)


def operator_permissions(username: str) -> set:
    from vnc_remote_secure.security.operator_users import get_permissions
    return get_permissions(username)


# --- Revocation (shared state) ----------------------------------------


def mark_session_revoked(sid: str, exp: int) -> None:
    from vnc_remote_secure.security.revocation import mark_op_session_revoked
    mark_op_session_revoked(sid, exp)


def bump_user_epoch(username: str) -> None:
    from vnc_remote_secure.security.revocation import bump_op_user_epoch
    bump_op_user_epoch(username)


def shared_backend():
    from vnc_remote_secure.security.shared_state import get_backend
    return get_backend()


# --- Audit -------------------------------------------------------------


def audit(event: str, user: str, detail: str = '',
          result: str = '') -> None:
    from vnc_remote_secure.security.audit import audit_event
    kw = {'detail': detail}
    if result:
        kw['result'] = result
    audit_event(event, user=user, **kw)


# --- Step-up -----------------------------------------------------------


def step_up_error(username: str, action: str) -> str | None:
    from vnc_remote_secure.security.step_up_auth import require_step_up
    return require_step_up(username, action)


# --- WebAuthn credentials ----------------------------------------------


def credential_list(username: str) -> list:
    from vnc_remote_secure.security.webauthn import list_credentials
    return list_credentials(username)


def credential_delete(credential_id: str, username: str) -> bool:
    from vnc_remote_secure.security.webauthn import delete_credential
    return delete_credential(credential_id, username)


def credential_rename(credential_id: str, name: str) -> bool:
    from vnc_remote_secure.security.webauthn import _load_store, _save_store, _store_lock
    with _store_lock():
        store = _load_store()
        if credential_id not in store:
            return False
        store[credential_id]['name'] = name
        _save_store(store)
    return True


def webauthn_gate_error() -> str | None:
    from vnc_remote_secure.security.webauthn import rp_config_error, webauthn_available
    if not webauthn_available():
        return 'WebAuthn is not enabled'
    return rp_config_error()


def webauthn_begin(username: str, rp_id: str, rp_name: str) -> dict:
    from vnc_remote_secure.security.webauthn import begin_registration
    return begin_registration(username, username, rp_id, rp_name)


def webauthn_complete(username: str, credential: dict, rp_id: str,
                      origin: str, name: str) -> tuple[bool, str]:
    from vnc_remote_secure.security.webauthn import complete_registration
    return complete_registration(username, credential, rp_id, origin,
                                 name=name)


# --- MFA policy ----------------------------------------------------------


def mfa_required() -> bool:
    from vnc_remote_secure.security.mfa import mfa_required_for_login
    return mfa_required_for_login()


def mfa_available() -> bool:
    from vnc_remote_secure.security.mfa import is_mfa_enabled
    return is_mfa_enabled()
