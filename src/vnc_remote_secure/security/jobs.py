"""Destructive-operation job tracking + operator tombstones.

Lives on the shared-state backend so every service process sees the
same records (AGENTS.md F-018 rule — no process-local security state).

Two mechanisms:

* **Jobs** — a bounded ledger of destructive mutations
  (``running`` → ``done``/``failed``). Synchronous use cases record a
  job anyway: the record survives the audit log's append-only
  semantics as a queryable state machine, and future async work
  (drain, backup restore) can leave jobs in ``running``.
* **Tombstones** — deleting an operator snapshots its non-secret
  record (role, created_at) for ``_TOMBSTONE_TTL`` so a mistaken or
  hostile deletion can be undone via the restore use case. Password
  hashes are never tombstoned — a restored account starts disabled
  with a random password and must be re-enabled + re-passworded by
  an admin.
"""
from __future__ import annotations

import json
import logging
import secrets
import time

logger = logging.getLogger(__name__)

_NS_JOBS = 'ops_jobs'
_NS_TOMBSTONES = 'operator_tombstones'
_JOB_TTL = 24 * 3600           # jobs are a recent-ops ledger
_TOMBSTONE_TTL = 30 * 86400    # a month to notice a bad deletion
_MAX_SCAN = 500                # never walk more keys than this


def _be():
    from vnc_remote_secure.security.shared_state import get_backend
    return get_backend()


def job_start(kind: str, actor: str, target: str = '',
              detail: str = '') -> str:
    """Record a running job; returns the job id (best-effort — a
    backend failure must not block the operation itself)."""
    jid = secrets.token_hex(8)
    try:
        payload = {
            'id': jid, 'kind': kind, 'actor': actor,
            'target': target, 'state': 'running',
            'started_at': time.time(), 'finished_at': None,
            'detail': detail[:256], 'error': None,
        }
        _be().set_ttl(_NS_JOBS, jid, json.dumps(payload), _JOB_TTL)
    except Exception:  # noqa: BLE001 - tracking must not break the op
        logger.debug('job_start failed', exc_info=True)
    return jid


def _update(jid: str, **fields) -> None:
    try:
        be = _be()
        raw = be.get(_NS_JOBS, jid)
        if raw is None:
            return
        payload = json.loads(raw)
        payload.update(fields)
        be.set_ttl(_NS_JOBS, jid, json.dumps(payload), _JOB_TTL)
    except Exception:  # noqa: BLE001
        logger.debug('job update failed', exc_info=True)


def job_finish(jid: str, detail: str = '') -> None:
    _update(jid, state='done', finished_at=time.time(),
            detail=detail[:256] or None)


def job_fail(jid: str, error: str) -> None:
    _update(jid, state='failed', finished_at=time.time(),
            error=str(error)[:256])


def list_jobs(limit: int = 100) -> list:
    """Newest-first job records, bounded by ``limit``."""
    try:
        be = _be()
        out = []
        for key in be.list_keys(_NS_JOBS)[:_MAX_SCAN]:
            raw = be.get(_NS_JOBS, key)
            if raw is None:
                continue
            try:
                out.append(json.loads(raw))
            except (ValueError, TypeError):
                continue
        out.sort(key=lambda j: j.get('started_at', 0), reverse=True)
        return out[:limit]
    except Exception:  # noqa: BLE001
        return []


# --- Operator tombstones -------------------------------------------------

def tombstone_save(username: str, record: dict) -> None:
    """Snapshot the non-secret parts of a deleted operator."""
    try:
        payload = {
            'username': username,
            'role': record.get('role', 'viewer'),
            'created_at': record.get('created_at'),
            'deleted_at': time.time(),
        }
        _be().set_ttl(_NS_TOMBSTONES, username, json.dumps(payload),
                      _TOMBSTONE_TTL)
    except Exception:  # noqa: BLE001
        logger.debug('tombstone save failed', exc_info=True)


def tombstone_get(username: str) -> dict | None:
    try:
        raw = _be().get(_NS_TOMBSTONES, username)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def tombstone_remove(username: str) -> None:
    try:
        _be().delete(_NS_TOMBSTONES, username)
    except Exception:  # noqa: BLE001
        pass


def tombstones() -> list:
    """All outstanding tombstones, newest deletions first."""
    try:
        be = _be()
        out = []
        for key in be.list_keys(_NS_TOMBSTONES):
            raw = be.get(_NS_TOMBSTONES, key)
            if raw is None:
                continue
            try:
                out.append(json.loads(raw))
            except (ValueError, TypeError):
                continue
        out.sort(key=lambda t: t.get('deleted_at', 0), reverse=True)
        return out
    except Exception:  # noqa: BLE001
        return []
