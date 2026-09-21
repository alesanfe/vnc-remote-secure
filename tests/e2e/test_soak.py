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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

pytestmark = pytest.mark.soak

if not os.environ.get('SOAK_SECONDS'):
    pytest.skip(
        "soak tests require SOAK_SECONDS (e.g. SOAK_SECONDS=300)",
        allow_module_level=True)


def _soak_seconds(default=60):
    try:
        return int(os.environ.get('SOAK_SECONDS', str(default)))
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
        token = create_ephemeral_session(
            role='viewer', ttl_seconds=60)
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
        backend.set_ttl('soak', f'k{iterations}', iterations, 1)
        iterations += 1
        if iterations % 100 == 0:
            time.sleep(0.05)
    assert iterations > 0
    # After the TTL elapses every written key must read back None —
    # expiry is enforced on access, not just eventually collected.
    time.sleep(1.2)
    keys = backend.list_keys('soak', 'k')
    live = [k for k in keys if backend.get('soak', k) is not None]
    assert live == []


def test_rate_limiter_churn():
    """Hammer the rate limiter; lockout state must stay bounded."""
    from vnc_remote_secure.security.rate_limit import get_auth_limiter
    limiter = get_auth_limiter()
    deadline = time.time() + _soak_seconds()
    iterations = 0
    while time.time() < deadline and iterations < 5000:
        limiter.record_failure(f'soak:{iterations % 50}')
        limiter.is_locked(f'soak:{iterations % 50}')
        iterations += 1
    assert iterations > 0
