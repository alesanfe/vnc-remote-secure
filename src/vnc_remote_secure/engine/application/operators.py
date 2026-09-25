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
    if excluding != 'admin' and stores.env('LANDING_PASSWORD'):
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
    detail_bits: list[str] = []
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
        detail_bits.append(
            f'role={rec.get("role")}->{role}')
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
        detail_bits.append('disabled' if disabled else 'enabled')
        changed.append('disabled')
        if disabled:
            revoke = True

    if password is not None:
        if not stores.operator_set_password(username, password):
            raise UseCaseError(ERR_INVALID, 'password update failed')
        detail_bits.append('password')
        changed.append('password')
        revoke = True

    if revoke:
        revoke_operator_sessions(username)
    # One audit entry per request — the detail names what changed.
    _audit('operator_updated', actor,
           f'target={username} {" ".join(detail_bits)}')
    return {
        'record': _store()[username],
        'changed': changed,
        'sessions_revoked': revoke,
    }


def delete_operator(actor: str, username: str) -> None:
    """Remove the account and kill its sessions. The last viable
    administrator is undeletable.

    A tombstone (non-secret snapshot: role, timestamps — never the
    password hash) is kept for ~30 days so a bad deletion can be
    undone via :func:`restore_operator`."""
    rec = _store().get(username)
    if rec is None:
        raise UseCaseError(ERR_NOT_FOUND, 'operator not found')
    if _is_admin(username) \
            and viable_admin_count(excluding=username) == 0:
        raise UseCaseError(
            ERR_LAST_ADMIN,
            'would delete the last viable administrator')
    jid = stores.job_start('operator.delete', actor, username)
    try:
        stores.tombstone_save(username, rec)
        if not stores.operator_remove(username):
            raise UseCaseError(ERR_INVALID, 'operator delete failed')
        revoke_operator_sessions(username)
    except UseCaseError as exc:
        stores.job_fail(jid, exc.detail or exc.code)
        raise
    except Exception as exc:  # noqa: BLE001
        stores.job_fail(jid, str(exc))
        raise
    stores.job_finish(jid, 'deleted; tombstone kept')
    _audit('operator_deleted', actor, f'target={username}')


def deleted_operators() -> list:
    """Outstanding tombstones — restore candidates for the UI."""
    return stores.tombstones()


def restore_operator(actor: str, username: str) -> dict:
    """Undo a deletion: recreate the account from its tombstone.

    The restored operator starts **disabled** with a random,
    unknowable password — an admin must explicitly re-enable it and
    set a new password. Passkeys are NOT restored (they were deleted
    with the account's credential records)."""
    import secrets as _secrets
    tomb = stores.tombstone_get(username)
    if tomb is None:
        raise UseCaseError(
            ERR_NOT_FOUND, 'no deleted account for this username')
    if username in _store():
        raise UseCaseError(ERR_CONFLICT, 'operator already exists')
    jid = stores.job_start('operator.restore', actor, username)
    try:
        stores.operator_add(
            username, _secrets.token_urlsafe(24),
            tomb.get('role', 'viewer'))
        stores.operator_set_disabled(username, True)
        stores.tombstone_remove(username)
    except Exception as exc:  # noqa: BLE001
        stores.job_fail(jid, str(exc))
        raise UseCaseError(ERR_INVALID, 'operator restore failed') \
            from exc
    stores.job_finish(jid, 'restored disabled')
    _audit('operator_restored', actor, f'target={username}')
    return _store()[username]


def revoke_sessions(actor: str, username: str) -> None:
    """Explicitly revoke all of an operator's live sessions."""
    if _store().get(username) is None:
        raise UseCaseError(ERR_NOT_FOUND, 'operator not found')
    jid = stores.job_start('operator.sessions_revoke', actor,
                           username)
    revoke_operator_sessions(username)
    stores.job_finish(jid)
    _audit('operator_sessions_revoked', actor, f'target={username}')
