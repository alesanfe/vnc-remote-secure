"""Maintenance-mode use case — a system-wide gate, so it sits behind
the admin umbrella AND a step-up mark (declared on the route).

Rules owned here:

* ``drain_timeout`` schedules a deferred drain (existing share links
  keep their TTL until the deadline, then fail closed);
  ``drain=True`` sweeps them immediately;
* enabling maintenance while already active refreshes the window —
  harmless, the flag file is overwritten with a new generation;
* disabling clears the window; the drain markers of the old
  generation are cleaned by ``set_maintenance`` itself.
"""
from __future__ import annotations

import time

from vnc_remote_secure.engine.domain.decision import (
    ERR_INVALID,
    UseCaseError,
)
from vnc_remote_secure.engine.infrastructure import stores

_MAX_DRAIN_TIMEOUT = 24 * 3600


def set_maintenance(actor: str, active: bool, reason: str = '',
                    drain: bool = False,
                    drain_timeout: int = 0) -> dict:
    """Toggle maintenance mode; returns the resulting info dict."""
    reason = reason[:256]
    if drain_timeout < 0 or drain_timeout > _MAX_DRAIN_TIMEOUT:
        raise UseCaseError(
            ERR_INVALID,
            f'drain_timeout must be 0..{_MAX_DRAIN_TIMEOUT}s')
    drain_at = (time.time() + drain_timeout
                if active and drain_timeout > 0 else None)
    stores.maintenance_set(
        active, by=f'api:{actor}', reason=reason, drain_at=drain_at)
    drained = 0
    if active and drain:
        drained = stores.maintenance_drain()
    stores.audit(
        'maintenance_changed', actor,
        f'active={int(bool(active))}'
        + (f' drained={drained}' if drained else '')
        + (f' reason={reason}' if reason else ''))
    info = stores.maintenance_info() or {}
    return {
        'active': stores.maintenance_active(),
        'drained_now': drained,
        'drain_at': drain_at,
        'info': info,
    }


def maintenance_status() -> dict:
    """Current maintenance state for GET /maintenance."""
    return {
        'active': stores.maintenance_active(),
        'info': stores.maintenance_info() or {},
    }
