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
from vnc_remote_secure.engine.infrastructure import stores

# Share-link permissions that grant administrative power — minting a
# link carrying any of these requires the operator to hold 'admin:*',
# otherwise an 'admin_sessions' operator could hand out admin links.
ADMINISH_PERMS = {
    'admin', 'admin_users', 'admin_config', 'admin_audit',
}

# Resources a share link may be scoped to.
RESOURCES = {'desktop', 'terminal', 'audio', 'gamepad', 'files'}


def _audit(event: str, actor: str, detail: str,
           result: str = '') -> None:
    stores.audit(event, actor, detail, result=result)


def _notify(title: str, message: str, severity: str = 'info') -> None:
    """Best-effort alert-channel notification (Discord/webhook/email).

    Session lifecycle events are worth paging about — a share link
    activating means an external party just gained remote access.
    Never raises: alerting must not break the mutation it follows.
    """
    try:
        stores.alert_notify(title, message, severity)
    except Exception:  # noqa: BLE001
        pass


_LABEL_MAX = 64


def _validate_label(label: str | None) -> str | None:
    """Normalize an operator tag — bounded, printable, single-line.

    Labels are inventory metadata: they ride along in session records
    so the admin list can group "soporte Juan" links, but they never
    influence authorization. Anything else is an injection surface
    (CR/LF into logs, markup into tooltips), so it's rejected here.
    """
    if label is None:
        return None
    label = str(label).strip()
    if not label:
        return None
    if len(label) > _LABEL_MAX:
        raise UseCaseError(
            ERR_INVALID, f'label must be ≤ {_LABEL_MAX} chars')
    if any(ord(c) < 32 or c == '\x7f' for c in label):
        raise UseCaseError(
            ERR_INVALID, 'label must not contain control characters')
    return label


def create_share_link(actor: str, actor_perms: set, *,
                      role: str, permissions: set | None,
                      ttl: int, single_use: bool, view_only: bool,
                      no_terminal: bool, allowed_ip: str | None,
                      resource: str | None, max_uses: int,
                      label: str | None = None) -> tuple:
    """Create an ephemeral share-link session.

    Returns ``(session, signed_token)``; raises ``UseCaseError`` on a
    delegation violation. The caller (Backend) already validated the
    primitive types — this enforces the *authority* rules.
    """
    requested = (permissions if permissions is not None
                 else stores.session_roles()[role])
    if stores.expand_session_permissions(requested) & ADMINISH_PERMS \
            and 'admin:*' not in actor_perms:
        _audit('api_permission_denied', actor,
               'share-link with admin permissions')
        raise UseCaseError(
            ERR_PERMISSION,
            'admin-granting share links require admin:*')
    # Store failures propagate — the transport maps them to 500.
    session, signed = stores.session_store().create(
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
        label=_validate_label(label),
    )
    _notify('Share link created',
            f'actor={actor} role={role} resource={resource or "*"} '
            f'ttl={ttl}s single_use={single_use}')
    return session, signed


def revoke_share_link(actor: str, token_id: str) -> bool:
    """Revoke one share link by its public id. Returns whether the
    token existed — the transport decides how much to disclose."""
    revoked = stores.revoke_ephemeral_token(token_id)
    _audit('portal_session_revoke', actor, f'token_id={token_id}',
           result='success' if revoked else 'failure')
    if revoked:
        _notify('Share link revoked', f'actor={actor} id={token_id}',
                'warning')
    return bool(revoked)


def revoke_all_share_links(actor: str) -> int:
    """Emergency kill-switch: revoke every live share link."""
    store = stores.session_store()
    stores.session_refresh(store)
    count = 0
    for s in list(store.list_active()):
        if stores.revoke_ephemeral_token(s['token_id']):
            count += 1
    _audit('portal_session_revoke_all', actor, f'count={count}')
    if count:
        _notify('All share links revoked',
                f'actor={actor} count={count}', 'error')
    return count


def revoke_share_links_by(actor: str, created_by: str) -> int:
    """Revoke every live share link minted by *created_by* — the
    offboarding/compromised-credential kill operation."""
    store = stores.session_store()
    stores.session_refresh(store)
    count = 0
    for s in list(store.list_active()):
        if s.get('created_by') == created_by \
                and stores.revoke_ephemeral_token(s['token_id']):
            count += 1
    _audit('portal_session_revoke_user', actor,
           f'target={created_by} count={count}')
    return count


def get_share_link(token_id: str) -> dict | None:
    """Resolve one share-link record by its public ``token_id``.

    Returns the serialized session dict (the same shape the inventory
    emits) or None when no retained session carries that id —
    expired-and-reaped records look identical to unknown ids, so the
    transport answers a plain 404 without disclosing which.
    """
    store = stores.session_store()
    stores.session_refresh(store)
    for s in store.list_all():
        if s.get('token_id') == token_id:
            return s
    return None


def share_link_connections(token_id: str) -> list:
    """Live WebSocket connections carrying this share link.

    Resolves the public fingerprint to the internal token (kept
    inside the store) and reads the process-local registry — the
    answer is live data, not the persisted forensic stamps."""
    store = stores.session_store()
    session = store.find_by_token_id(token_id)
    if session is None:
        return []
    try:
        return stores.ws_connection_info(session.token)
    except Exception:  # noqa: BLE001 - live data is best-effort
        return []


# Session-center inventory filters.
LIST_FILTERS = {'active', 'revoked', 'all'}


def list_share_links(status: str = 'active') -> list:
    """Share-link records for the admin inventory.

    ``status`` selects the view: ``active`` (default), ``revoked``
    (still retained), or ``all`` (history, including expired records
    not yet reaped by cleanup).
    """
    if status not in LIST_FILTERS:
        raise UseCaseError(
            ERR_INVALID, f'unknown status filter: {status}')
    store = stores.session_store()
    stores.session_refresh(store)
    if status == 'revoked':
        return list(store.list_revoked())
    if status == 'all':
        return list(store.list_all())
    return list(store.list_active())
