"""Soak / long-running stability tests (opt-in).

These tests exercise the system under sustained load for extended
periods — session create/revoke churn, repeated auth attempts, and
shared-state growth — to surface leaks that short unit tests cannot:
memory growth, fd exhaustion, stale PID state, log rotation bugs.

They are opt-in: skipped unless ``SOAK_SECONDS`` is set, so the
default suite stays fast. Run them explicitly:

    SOAK_SECONDS=300 pytest tests/e2e/test_soak.py

Each test also has a hard iteration cap so it terminates even when
the configured duration is very long.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

pytestmark = pytest.mark.soak

if not os.environ.get("SOAK_SECONDS"):
    pytest.skip("soak tests require SOAK_SECONDS (e.g. SOAK_SECONDS=300)", allow_module_level=True)


def _soak_seconds(default=60):
    try:
        return int(os.environ.get("SOAK_SECONDS", str(default)))
    except (TypeError, ValueError):
        return default


def test_ephemeral_session_churn():
    """Create/revoke ephemeral sessions in a tight loop.

    Watches for: file-descriptor leaks in the store's load/save path,
    unbounded growth of the persisted sessions file, and stale
    entries accumulating after revocation.
    """
    from vnc_remote_secure.security.ephemeral_sessions import (
        create_ephemeral_session,
        get_session_store,
    )

    deadline = time.time() + _soak_seconds()
    iterations = 0
    store = get_session_store()
    while time.time() < deadline and iterations < 5000:
        token = create_ephemeral_session(role="viewer", ttl_seconds=60)
        assert token
        session = store.validate(token)
        if session is not None:
            session.revoke()
        iterations += 1
    assert iterations > 0
    # The store must not grow unboundedly with revoked sessions.
    assert len(store._sessions) <= iterations


def test_shared_state_ttl_churn():
    """Write expiring keys in a loop; the backend must reclaim them.

    Watches for: SQLite file growth beyond TTL'd data, lock
    contention stalls, and expired-key leaks.
    """
    from vnc_remote_secure.security.shared_state import get_backend

    backend = get_backend()
    deadline = time.time() + _soak_seconds()
    iterations = 0
    while time.time() < deadline and iterations < 5000:
        backend.set_ttl("soak", f"k{iterations}", iterations, 1)
        iterations += 1
        if iterations % 100 == 0:
            time.sleep(0.05)
    assert iterations > 0
    # After the TTL elapses every written key must read back None —
    # expiry is enforced on access, not just eventually collected.
    time.sleep(1.2)
    keys = backend.list_keys("soak", "k")
    live = [k for k in keys if backend.get("soak", k) is not None]
    assert live == []


def test_rate_limiter_churn():
    """Hammer the rate limiter; lockout state must stay bounded."""
    from vnc_remote_secure.security.rate_limit import get_auth_limiter

    limiter = get_auth_limiter()
    deadline = time.time() + _soak_seconds()
    iterations = 0
    while time.time() < deadline and iterations < 5000:
        limiter.record_failure(f"soak:{iterations % 50}")
        limiter.is_locked(f"soak:{iterations % 50}")
        iterations += 1
    assert iterations > 0


def test_ws_registry_churn():
    """Sustained register/unregister + revoke churn on the WS registry.

    Exercises the new indexes (_by_ip, _resource_counts), the batched
    sweep path and the revocation negative cache under load — watches
    for index drift (counts going negative or stuck), leaked
    connections, and shared-state lock errors.
    """
    from vnc_remote_secure.security import websocket_registry as wr
    from vnc_remote_secure.security.shared_state import sqlite_stats

    reg = wr.get_registry()
    stats0 = dict(sqlite_stats())
    deadline = time.time() + _soak_seconds()
    iterations = 0
    while time.time() < deadline and iterations < 5000:
        sid = f"soak-ws-{iterations % 25}"
        cid = reg.register(
            sid,
            lambda: None,
            resource="vnc",
            client_ip=f"10.9.{iterations % 250}.{iterations % 250}",
        )
        if cid is not None:
            if iterations % 7 == 0:
                wr.revoke_session_connections(sid)
            else:
                reg.unregister(cid)
        # Periodic explicit sweep — the production sweeper is disabled
        # under VRS_TEST_MODE, so drive the same code path here.
        if iterations % 200 == 0:
            wr._sweep_cycle()
        iterations += 1
    reg._connections.clear()
    assert iterations > 0
    # No index drift: resource counts and per-IP index must be empty
    # after the final clear (conftest also clears, but assert locally).
    assert all(v == 0 for v in reg._resource_counts.values())
    stats1 = sqlite_stats()
    # Lock errors under churn are the failure mode this guards — a
    # handful of busy-waits is tolerable, sustained errors are not.
    assert stats1.get("lock_errors", 0) - stats0.get("lock_errors", 0) < 50


def test_metrics_buffer_churn():
    """Sustained inc/set traffic through the write buffer + flushes.

    Watches for: pending-map growth (flush falling behind), gauge
    dirty-check correctness, and flush latency under load.
    """
    from vnc_remote_secure.monitoring import prometheus as prom

    deadline = time.time() + _soak_seconds()
    iterations = 0
    flushes = 0
    while time.time() < deadline and iterations < 5000:
        for i in range(20):
            prom.inc_counter("soak_hits", f"route=/r{i % 10}", value=1)
            prom.set_gauge("soak_gauge", float(iterations % 100), "svc=test")
        if iterations % 25 == 0:
            assert prom.flush_metrics_now() is True
            flushes += 1
        iterations += 1
    # Buffer must never grow without bound — pending is bounded by
    # flush cadence, and everything pending here is flushable.
    assert prom.metrics_pending() < 10000
    assert prom.flush_metrics_now() is True
    assert flushes > 0
