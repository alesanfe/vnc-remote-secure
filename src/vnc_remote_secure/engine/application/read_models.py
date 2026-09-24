"""Read models for the admin views — shaped data the transport
serializes. Queries are pure: no mutation, no audit side effects.

Keeping these behind ``engine/application`` means ``services/api_v1``
handlers never reach into ``security/*`` or ``core/*`` for reads —
the persistence or telemetry backend can move without touching the
API surface.
"""
from __future__ import annotations

from vnc_remote_secure.engine.infrastructure import stores


def operators_index() -> list:
    """Store records with their effective permission set attached."""
    store = stores.operator_load_store()
    users = []
    for username, rec in sorted(store.items()):
        users.append({
            'username': username,
            'role': rec.get('role'),
            'disabled': bool(rec.get('disabled')),
            'created_at': rec.get('created_at'),
            'permissions': sorted(stores.operator_permissions(username)),
        })
    return users


def operator_detail(username: str) -> dict | None:
    """Operator record + display metadata the admin UI shows.

    ``deletion_allowed``/``blocking_reasons`` are display metadata —
    the use case layer still enforces deletion at apply time.
    """
    from vnc_remote_secure.engine.application.operators import viable_admin_count
    rec = stores.operator_load_store().get(username)
    if rec is None:
        return None
    blocking = []
    if rec.get('role') == 'admin' \
            and viable_admin_count(excluding=username) == 0:
        blocking.append('last_viable_administrator')
    return {
        'username': username,
        'role': rec.get('role'),
        'disabled': bool(rec.get('disabled')),
        'created_at': rec.get('created_at'),
        'permissions': sorted(stores.operator_permissions(username)),
        'passkey_count': len(stores.credential_list(username)),
        'deletion_allowed': not blocking,
        'blocking_reasons': blocking,
    }


def audit_page(limit: int, event: str | None = None,
               before_seq: int | None = None,
               user: str | None = None,
               result: str | None = None) -> dict:
    """One cursor page of audit entries.

    ``before_seq`` is the opaque cursor (seq of the previous page's
    last entry); ``next_cursor`` repeats it only when more pages
    exist, so the client can stop cleanly.
    """
    entries = stores.audit_read(
        limit=limit + 1, event=event, before_seq=before_seq,
        user=user, result=result)
    has_more = len(entries) > limit
    entries = entries[:limit]
    return {
        'entries': entries,
        'next_cursor': (entries[-1].get('seq')
                        if has_more and entries else None),
        'has_more': has_more,
    }


def audit_integrity() -> dict:
    intact, message = stores.audit_verify_chain()
    return {'intact': intact, 'message': message}


def config_vars() -> list:
    """Effective configuration entries (already secret-redacted)."""
    return stores.config_effective()


def backup_paths() -> list:
    """Backup file paths — the transport stats/serializes them."""
    return stores.backups_paths()


def posture() -> dict:
    return stores.posture_report()


def doctor() -> dict:
    return stores.doctor_report()


def health() -> dict:
    return stores.health_report()


def jobs(limit: int = 100) -> list:
    """Recent destructive-operation jobs, newest first."""
    limit = max(1, min(int(limit), 500))
    return stores.jobs_list(limit)


def deleted_operators() -> list:
    """Operator tombstones — the restore candidates."""
    from vnc_remote_secure.engine.application.operators import (
        deleted_operators as _deleted,
    )
    return _deleted()
