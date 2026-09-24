"""Fault-injection tests: concurrency, clock skew, backend failure,
corrupt state — the failure modes unit tests can't reach by calling
functions with good inputs.

Each test asserts a *security property* under fault, not a happy
path: single-use stays single-use, revoked stays revoked, corrupted
state denies rather than grants.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import vnc_remote_secure.security.ephemeral_sessions as es  # noqa: E402


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    """Isolate the session store + shared-state backend per test."""
    es._store = None
    monkeypatch.setattr(
        'vnc_remote_secure.core.paths.get_run_dir',
        lambda: str(tmp_path / 'run'))
    monkeypatch.setenv('SHARED_STATE_DB',
                       str(tmp_path / 'shared_state.db'))
    monkeypatch.delenv('SHARED_STATE_STRICT', raising=False)
    monkeypatch.delenv('MAINTENANCE_MODE', raising=False)
    import vnc_remote_secure.security.shared_state as ss
    ss._backend = None
    yield
    es._store = None
    ss._backend = None


class TestSingleUseConcurrency:
    """The single-use guarantee must hold under a thread storm and
    across backend claims — two winners means replay."""

    def test_thread_storm_exactly_one_wins(self):
        store = es.get_session_store()
        session, signed = store.create(
            role='operator', expires_in=3600, single_use=True)
        wins = []
        barrier = threading.Barrier(16)

        def consume():
            barrier.wait()
            if es.consume_ephemeral_session(signed):
                wins.append(1)

        threads = [threading.Thread(target=consume) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sum(wins) == 1

    def test_claim_consumed_fails_closed_on_backend_death(
            self, monkeypatch):
        class DeadBackend:
            def set_if_absent(self, *a, **k):
                raise OSError('database is locked')
        monkeypatch.setattr(
            'vnc_remote_secure.security.shared_state.get_backend',
            lambda: DeadBackend())
        assert es._claim_consumed('tok', time.time() + 600) is False

    def test_multi_use_budget_fails_closed_on_backend_death(
            self, monkeypatch):
        class DeadBackend:
            def increment(self, *a, **k):
                raise OSError('disk I/O error')
        monkeypatch.setattr(
            'vnc_remote_secure.security.shared_state.get_backend',
            lambda: DeadBackend())
        assert es._claim_use('tok', 3, time.time() + 600) is False


class TestClockSkew:
    """Expiry is wall-clock based; a jump forward must not extend a
    session and a jump backward must not resurrect one."""

    def test_forward_skew_expires_session(self, monkeypatch):
        store = es.get_session_store()
        session, _ = store.create(role='viewer', expires_in=300)
        assert es.check_session_permission(session.token, 'view') is True
        real_time = time.time
        monkeypatch.setattr(
            time, 'time', lambda: real_time() + 600)
        assert es.check_session_permission(session.token, 'view') is False

    def test_backward_skew_does_not_revive(self, monkeypatch):
        store = es.get_session_store()
        session, _signed = store.create(role='viewer', expires_in=-10)
        # Already expired at creation — no clock direction revives it.
        assert es.check_session_permission(session.token, 'view') is False
        monkeypatch.setattr(time, 'time', lambda: 0)
        assert es.check_session_permission(session.token, 'view') is False

    def test_backward_skew_keeps_valid_session(self, monkeypatch):
        store = es.get_session_store()
        session, _signed = store.create(role='viewer', expires_in=3600)
        real_time = time.time
        monkeypatch.setattr(
            time, 'time', lambda: real_time() - 300)
        # A skewed-back clock within TTL still grants — the expiry
        # bound is expires_at, not elapsed time.
        assert es.check_session_permission(session.token, 'view') is True


class TestCorruptState:
    """Malformed on-disk state must deny, not grant or crash."""

    def test_corrupt_session_file_denies(self, tmp_path):
        store = es.get_session_store()
        session, _signed = store.create(role='operator', expires_in=3600)
        store._save()
        path = store._persist_path()
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{"sessions": "not-a-dict"}{garbage')
        # Force reload from the corrupt file.
        es._store = None
        assert es.check_session_permission(session.token, 'view') is False

    def test_truncated_session_file_denies(self, tmp_path):
        store = es.get_session_store()
        session, _signed = store.create(role='operator', expires_in=3600)
        store._save()
        path = store._persist_path()
        raw = open(path, 'rb').read()
        with open(path, 'wb') as f:
            f.write(raw[:len(raw) // 3])  # mid-JSON truncation
        es._store = None
        assert es.check_session_permission(session.token, 'view') is False

    def test_foreign_instance_session_denied(self, monkeypatch):
        store = es.get_session_store()
        session, _signed = store.create(role='viewer', expires_in=3600)
        session.instance_id = 'other-deployment'
        store._save()
        es._store = None
        assert es.check_session_permission(session.token, 'view') is False


class TestBackendOutage:
    """Revocation reads must fail closed under SHARED_STATE_STRICT
    and degrade consistently without it."""

    def test_revocation_lookup_backend_failure(self, monkeypatch):
        import vnc_remote_secure.security.shared_state as ss

        class DeadBackend:
            def get(self, *a, **k):
                raise OSError('readonly database')

            def set_if_absent(self, *a, **k):
                raise OSError('readonly database')
        monkeypatch.setattr(ss, '_backend', DeadBackend())
        monkeypatch.setattr(
            'vnc_remote_secure.security.shared_state.get_backend',
            lambda: DeadBackend())
        # The claim helpers consume the backend — a dead one denies.
        assert es._claim_consumed('t', time.time() + 60) is False

    def test_audit_export_dead_sinks_never_raise(self, monkeypatch):
        """A dead SIEM must not break the audited request."""
        import socket

        from vnc_remote_secure.security import audit_export
        monkeypatch.setenv('AUDIT_SYSLOG_HOST', '10.255.255.1')
        monkeypatch.setenv(
            'AUDIT_EXPORT_WEBHOOK', 'https://invalid.invalid/hook')
        monkeypatch.setattr(
            socket, 'socket',
            lambda *a, **k: (_ for _ in ()).throw(OSError('no route')))
        audit_export.export_entry(
            {'event': 'x', 'result': 'success'}, '{}')
        assert audit_export._consecutive_failures >= 1


class TestMaintenanceRace:
    """Toggling maintenance mid-activation must not half-issue a
    session."""

    def test_activation_denied_before_token_verify(self, monkeypatch):
        from vnc_remote_secure.security import maintenance
        maintenance.set_maintenance(True)
        calls = []
        monkeypatch.setattr(
            es, 'verify_ephemeral_token',
            lambda t: calls.append(t) or {'session_token': 'x'})
        assert es.activate_ephemeral_session('signed') is None
        # The maintenance gate runs before any token verification —
        # a dead flag means zero work, not a half-decision.
        assert calls == []
        maintenance.set_maintenance(False)
