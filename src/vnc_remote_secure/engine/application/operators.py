"""Operator management use cases — domain rules the Backend invokes.

Each function takes validated primitives (never a request body) and
returns plain data; failures are ``UseCaseError`` with a public code
the transport maps to a status. Domain rules living here, not in the
route handler:

* the last viable administrator cannot be deleted, disabled or
  demoted;
* granting the admin role requires the admin umbrella on the actor;
* role/password/disable/delete changes revoke the target's live
  operator sessions via a per-user epoch mark.

Infrastructure access is funnelled through
``engine.infrastructure.stores`` — this module never sees HTTP and
never imports ``security/*`` directly.
"""
from __future__ import annotations

import os
import time

from vnc_remote_secure.engine.domain.decision import (
    ERR_CONFLICT,
    ERR_INVALID,
    ERR_LAST_ADMIN,
    ERR_NOT_FOUND,
    ERR_PERMISSION,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores

_OP_SESSION_TTL = 8 * 3600  # mirrors LandingHandler._OP_SESSION_TTL


def _store():
    return stores.operator_load_store()


def _audit(event: str, actor: str, detail: str) -> None:
    stores.audit(event, actor, detail)


def viable_admin_count(excluding: str = '') -> int:
    """Enabled operators holding the admin umbrella, minus one.

    The env bootstrap admin counts only while a LANDING_PASSWORD is
    configured — a demotion must never assume it silently exists.
    """
    count = 0
    if excluding != 'admin' and os.environ.get('LANDING_PASSWORD'):
        count += 1
    for name, rec in _store().items():
        if name != excluding and not rec.get('disabled') \
                and rec.get('role') == 'admin':
            count += 1
    return count


def _is_admin(username: str) -> bool:
    rec = _store().get(username)
    return rec is not None and rec.get('role') == 'admin'


def revoke_operator_sessions(username: str) -> None:
    """Kill every live vnc_op session for *username* — the cookies are
    stateless, so revocation records a per-user epoch in shared state
    and the verify path rejects anything issued before it."""
    stores.shared_backend().set_ttl(
        'op_revoked_users', username, str(time.time()),
        _OP_SESSION_TTL)


def create_operator(actor: str, actor_perms: set, username: str,
                    password: str, role: str, enabled: bool) -> dict:
    """Create a store operator. Password policy and username validity
    were enforced by the caller (validation layer); domain checks
    here: role known, admin-grant needs admin:*, duplicate is a
    conflict."""
    if role not in stores.operator_roles():
        raise UseCaseError(ERR_INVALID, f'unknown role {role!r}')
    if role == 'admin' and 'admin:*' not in actor_perms:
        _audit('api_permission_denied', actor, 'create admin operator')
        raise UseCaseError(
            ERR_PERMISSION, 'creating admin operators requires admin:*')
    try:
        stores.operator_add(username, password, role)
    except ValueError as exc:
        code = (ERR_CONFLICT if 'already exists' in str(exc)
                else ERR_INVALID)
        raise UseCaseError(code, str(exc)) from exc
    if not enabled:
        stores.operator_set_disabled(username, True)
    _audit('operator_created', actor, f'target={username} role={role}')
    return _store()[username]


def update_operator(actor: str, actor_perms: set, username: str,
                    *, role: str | None = None,
                    disabled: bool | None = None,
                    password: str | None = None) -> dict:
    """Apply the requested changes; returns
    ``{'record': ..., 'changed': [...], 'sessions_revoked': bool}``.

    Sensitive changes (role, disable, password) revoke the target's
    live sessions — a session must never keep a stale capability set.
    """
    rec = _store().get(username)
    if rec is None:
        raise UseCaseError(ERR_NOT_FOUND, 'operator not found')

    changed: list[str] = []
    revoke = False

    if role is not None:
        if role not in stores.operator_roles():
            raise UseCaseError(ERR_INVALID, f'unknown role {role!r}')
        if role != 'admin' and _is_admin(username) \
                and viable_admin_count(excluding=username) == 0:
            raise UseCaseError(
                ERR_LAST_ADMIN,
                'would remove the last viable administrator')
        if role == 'admin' and 'admin:*' not in actor_perms:
            raise UseCaseError(
                ERR_PERMISSION, 'granting admin requires admin:*')
        if not stores.operator_set_role(username, role):
            raise UseCaseError(ERR_INVALID, 'role update failed')
        _audit('operator_role_changed', actor,
               f'target={username} {rec.get("role")}->{role}')
        changed.append('role')
        revoke = True

    if disabled is not None:
        if disabled and _is_admin(username) \
                and viable_admin_count(excluding=username) == 0:
            raise UseCaseError(
                ERR_LAST_ADMIN,
                'would disable the last viable administrator')
        if not stores.operator_set_disabled(username, disabled):
            raise UseCaseError(ERR_INVALID, 'state update failed')
        _audit('operator_disabled' if disabled else 'operator_enabled',
               actor, f'target={username}')
        changed.append('disabled')
        if disabled:
            revoke = True

    if password is not None:
        if not stores.operator_set_password(username, password):
            raise UseCaseError(ERR_INVALID, 'password update failed')
        _audit('operator_password_changed', actor,
               f'target={username}')
        changed.append('password')
        revoke = True

    if revoke:
        revoke_operator_sessions(username)
    return {
        'record': _store()[username],
        'changed': changed,
        'sessions_revoked': revoke,
    }


def delete_operator(actor: str, username: str) -> None:
    """Remove the account and kill its sessions. The last viable
    administrator is undeletable."""
    if _store().get(username) is None:
        raise UseCaseError(ERR_NOT_FOUND, 'operator not found')
    if _is_admin(username) \
            and viable_admin_count(excluding=username) == 0:
        raise UseCaseError(
            ERR_LAST_ADMIN,
            'would delete the last viable administrator')
    if not stores.operator_remove(username):
        raise UseCaseError(ERR_INVALID, 'operator delete failed')
    revoke_operator_sessions(username)
    _audit('operator_deleted', actor, f'target={username}')


def revoke_sessions(actor: str, username: str) -> None:
    """Explicitly revoke all of an operator's live sessions."""
    if _store().get(username) is None:
        raise UseCaseError(ERR_NOT_FOUND, 'operator not found')
    revoke_operator_sessions(username)
    _audit('operator_sessions_revoked', actor, f'target={username}')
