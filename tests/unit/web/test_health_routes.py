"""Unit tests for web.routes.health — the Flask health blueprint.

Parallel to the stdlib handler tests (test_health_endpoints*): the
Flask blueprint serves the same endpoints on the user-UI port and
must emit the same status contract (200/503 mapping, auth gate,
rate-limited liveness).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

pytest.importorskip('flask')

import vnc_remote_secure.web.routes.health as health_mod  # noqa: E402
from vnc_remote_secure.web.application import create_app  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    # require_auth binds check_health_auth at decoration time, so the
    # real function is always used — enforce it by configuring a real
    # HEALTH_AUTH_TOKEN (otherwise the helper is loopback-open by
    # design).
    monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'good-token')
    app = create_app({})
    app.config['TESTING'] = True
    return app.test_client()


AUTH = {'Authorization': 'Bearer good-token'}


# ---------------------------------------------------------------------------
# /health aggregate
# ---------------------------------------------------------------------------

def test_health_503_when_down(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'down', 'services_up': 0,
                 'services_total': 3, 'services': {}})
    resp = client.get('/health', headers=AUTH)
    assert resp.status_code == 503


def test_health_200_when_healthy(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'healthy', 'services_up': 3,
                 'services_total': 3, 'services': {}})
    resp = client.get('/health', headers=AUTH)
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'healthy'


def test_health_200_when_degraded(client, monkeypatch):
    """Degraded is still 200 — a partial outage must not trip the
    monitor's hard-down alert for the aggregate endpoint."""
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'degraded', 'services_up': 2,
                 'services_total': 3, 'services': {}})
    resp = client.get('/health', headers=AUTH)
    assert resp.status_code == 200


def test_health_requires_auth(client):
    """With HEALTH_AUTH_TOKEN set, /health denies unauthenticated
    requests even on loopback."""
    resp = client.get('/health')
    assert resp.status_code == 401


def test_health_status_alias_works(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'healthy', 'services_up': 1,
                 'services_total': 1, 'services': {}})
    assert client.get('/health_status', headers=AUTH).status_code == 200
    assert client.get(
        '/health_status.json', headers=AUTH).status_code == 200


# ---------------------------------------------------------------------------
# /health/live — unauthenticated, rate-limited
# ---------------------------------------------------------------------------

def test_health_live_no_auth_needed(client):
    resp = client.get('/health/live')
    assert resp.status_code == 200
    assert resp.get_json() == {'status': 'alive'}


def test_health_live_rate_limited(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'check_rate_limit',
        lambda ip, max_requests=None, window_seconds=None: False)
    resp = client.get('/health/live')
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# /health/ready
# ---------------------------------------------------------------------------

def test_ready_503_when_a_service_down(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'degraded', 'services_up': 2,
                 'services_total': 3,
                 'services': {'vnc': True, 'terminal': True,
                              'novnc': False}})
    resp = client.get('/health/ready', headers=AUTH)
    assert resp.status_code == 503


def test_ready_200_when_all_up(client, monkeypatch):
    monkeypatch.setattr(
        health_mod, 'get_health_status',
        lambda: {'status': 'healthy', 'services_up': 2,
                 'services_total': 2,
                 'services': {'vnc': True, 'novnc': True}})
    resp = client.get('/health/ready', headers=AUTH)
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'ready'


def test_ready_requires_auth(client):
    assert client.get('/health/ready').status_code == 401


# ---------------------------------------------------------------------------
# /metrics, /audit, /audit/verify
# ---------------------------------------------------------------------------

def test_metrics_requires_auth(client):
    assert client.get('/metrics').status_code == 401


def test_metrics_returns_text_plain(client, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.monitoring.prometheus.metrics_handler',
        lambda: (b'# HELP x\nx 1\n', 200))
    resp = client.get('/metrics', headers=AUTH)
    assert resp.status_code == 200
    assert 'text/plain' in resp.content_type


def test_audit_clamps_limit(client, monkeypatch):
    seen = {}

    def fake_entries(limit, event=None):
        seen['limit'] = limit
        return []

    monkeypatch.setattr(
        'vnc_remote_secure.security.audit.get_audit_entries',
        fake_entries)
    resp = client.get('/audit?limit=99999', headers=AUTH)
    assert resp.status_code == 200
    assert seen['limit'] == 1000


def test_audit_verify_returns_chain(client, monkeypatch):
    monkeypatch.setattr(
        'vnc_remote_secure.security.audit.verify_chain',
        lambda: (True, 'ok'))
    resp = client.get('/audit/verify', headers=AUTH)
    assert resp.status_code == 200
    assert resp.get_json() == {'intact': True, 'message': 'ok'}


def test_health_all_500_on_failure(client, monkeypatch):
    def boom():
        raise RuntimeError('metrics broken')

    monkeypatch.setattr(health_mod, 'get_all_health', boom)
    resp = client.get('/health/all', headers=AUTH)
    assert resp.status_code == 500
