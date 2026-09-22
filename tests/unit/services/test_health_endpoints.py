"""Tests for /health/live, /health/ready, /health/services endpoints."""
import http.client
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import health


@pytest.fixture
def health_server(monkeypatch):
    """Start a health server on an ephemeral port."""
    monkeypatch.setattr(health, 'is_port_available', lambda port, host=None: True)
    server = health.start_health_server(port=0, host='127.0.0.1')
    yield server
    server.shutdown()
    server.server_close()


def test_health_live_returns_200(health_server):
    """Liveness endpoint always returns 200 if server is running."""
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health/live')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    assert resp.status == 200
    data = json.loads(body)
    assert data['status'] == 'alive'


def test_health_ready_returns_503_when_down(health_server):
    """Readiness returns 503 when all services are down."""
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health/ready')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    data = json.loads(body)
    assert resp.status == 503
    assert data['status'] == 'down'


def test_health_services_returns_dict(health_server):
    """Services endpoint returns per-service status with PID and port."""
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health/services')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    assert resp.status == 200
    data = json.loads(body)
    # status_all() returns a flat dict of service_name -> {pid, running, port}
    assert isinstance(data, dict)
    assert 'vnc' in data
    assert 'novnc' in data
    # Each entry must include the documented fields.
    for svc_name, svc_status in data.items():
        assert 'running' in svc_status, f"{svc_name} missing 'running'"
        assert 'pid' in svc_status, f"{svc_name} missing 'pid'"


def test_health_accepts_query_string(health_server):
    """GET /health?x=1 resolves like /health — not a 404.

    nginx forwards the request URI verbatim and cache-busting probes
    append query params; the stdlib handler must match the path the
    way Flask routes do (path-only).
    """
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health?cachebust=1')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    data = json.loads(body)
    # Never a routing-level 404 — either 200 (up/degraded) or 503 (down).
    assert resp.status in (200, 503)
    assert 'status' in data


def test_health_ready_503_when_degraded(health_server, monkeypatch):
    """Readiness is stricter than /health: degraded => 503.

    A 'degraded' aggregate means an enabled service is down — the
    deployment cannot serve all traffic, matching the Flask
    blueprint's all-services-listening requirement.
    """
    monkeypatch.setattr(
        health, 'get_health_status',
        lambda: {'status': 'degraded', 'services': {'vnc': True,
                                                    'novnc': False},
                 'services_up': 1, 'services_total': 2})
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health/ready')
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.status == 503


def test_health_returns_503_when_down(health_server):
    """Main /health returns 503 when status is down."""
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    data = json.loads(body)
    if data['status'] == 'down':
        assert resp.status == 503
    else:
        assert resp.status == 200


def test_health_requires_token_when_configured(health_server, monkeypatch):
    """With HEALTH_AUTH_TOKEN set, a missing/wrong Bearer must get 401 —
    the whole health auth surface is implicitly open otherwise."""
    monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'tok-secret-42')
    port = health_server.server_address[1]
    for path in ('/health', '/health/services', '/metrics'):
        conn = http.client.HTTPConnection('127.0.0.1', port)
        conn.request('GET', path)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 401, path


def test_health_accepts_correct_token(health_server, monkeypatch):
    monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'tok-secret-42')
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port)
    conn.request('GET', '/health',
                 headers={'Authorization': 'Bearer tok-secret-42'})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.status in (200, 503)  # auth passed; body status may vary
