"""Ephemeral share-link use cases — domain rules the Backend invokes.

The route handler validates the HTTP-level schema (types, ranges,
unknown keys); the use cases here own the *security* rules:

* privilege delegation — a link may only carry powers the creator
  holds; admin-granting permissions additionally require the admin
  umbrella (``admin:*``) on the actor;
* revocation semantics live in security.revocation (mark-first,
  idempotent, cleanup retryable) — this module delegates to it.

Both the API route and the CLI ``vnc-remote session`` commands must
call these use cases — never parallel implementations.
"""
from __future__ import annotations

from vnc_remote_secure.engine.domain.decision import (
    ERR_INVALID,
    ERR_PERMISSION,
    UseCaseError,
)

# Share-link permissions that grant administrative power — minting a
# link carrying any of these requires the operator to hold 'admin:*',
# otherwise an 'admin_sessions' operator could hand out admin links.
ADMINISH_PERMS = {
    'admin', 'admin_users', 'admin_config', 'admin_secrets',
    'admin_audit',
}

# Resources a share link may be scoped to.
RESOURCES = {'desktop', 'terminal', 'audio', 'gamepad'}


def _audit(event: str, actor: str, detail: str,
           result: str = '') -> None:
    from vnc_remote_secure.security.audit import audit_event
    kw = {'detail': detail}
    if result:
        kw['result'] = result
    audit_event(event, user=actor, **kw)


def create_share_link(actor: str, actor_perms: set, *,
                      role: str, permissions: set | None,
                      ttl: int, single_use: bool, view_only: bool,
                      no_terminal: bool, allowed_ip: str | None,
                      resource: str | None, max_uses: int) -> tuple:
    """Create an ephemeral share-link session.

    Returns ``(session, signed_token)``; raises ``UseCaseError`` on a
    delegation violation. The caller (Backend) already validated the
    primitive types — this enforces the *authority* rules.
    """
    from vnc_remote_secure.security.ephemeral_sessions import (
        ROLES,
        expand_permissions,
        get_session_store,
    )
    requested = permissions if permissions is not None else ROLES[role]
    if expand_permissions(requested) & ADMINISH_PERMS \
            and 'admin:*' not in actor_perms:
        _audit('api_permission_denied', actor,
               'share-link with admin permissions')
        raise UseCaseError(
            ERR_PERMISSION,
            'admin-granting share links require admin:*')
    # Store failures propagate — the transport maps them to 500.
    return get_session_store().create(
        expires_in=ttl,
        role=role,
        single_use=single_use,
        view_only=view_only,
        no_terminal=no_terminal,
        allowed_ip=allowed_ip,
        created_by=actor,
        resource=resource,
        max_uses=max_uses,
        permissions=permissions,
    )


def revoke_share_link(actor: str, token_id: str) -> bool:
    """Revoke one share link by its public id. Returns whether the
    token existed — the transport decides how much to disclose."""
    from vnc_remote_secure.security.ephemeral_sessions import revoke_session
    revoked = revoke_session(token_id)
    _audit('portal_session_revoke', actor, f'token_id={token_id}',
           result='success' if revoked else 'failure')
    return bool(revoked)


def revoke_all_share_links(actor: str) -> int:
    """Emergency kill-switch: revoke every live share link."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store, revoke_session
    store = get_session_store()
    store._load_if_changed()
    count = 0
    for s in list(store.list_active()):
        if revoke_session(s['token_id']):
            count += 1
    _audit('portal_session_revoke_all', actor, f'count={count}')
    return count


# Session-center inventory filters.
LIST_FILTERS = {'active', 'revoked', 'all'}


def list_share_links(status: str = 'active') -> list:
    """Share-link records for the admin inventory.

    ``status`` selects the view: ``active`` (default), ``revoked``
    (still retained), or ``all`` (history, including expired records
    not yet reaped by cleanup).
    """
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    if status not in LIST_FILTERS:
        raise UseCaseError(
            ERR_INVALID, f'unknown status filter: {status}')
    store = get_session_store()
    store._load_if_changed()
    if status == 'revoked':
        return list(store.list_revoked())
    if status == 'all':
        return list(store.list_all())
    return list(store.list_active())
