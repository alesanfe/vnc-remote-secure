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
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
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
    """Services endpoint returns per-service status."""
    port = health_server.server_address[1]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/health/services')
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    assert resp.status == 200
    data = json.loads(body)
    assert 'services' in data
    assert isinstance(data['services'], dict)
    assert 'vnc' in data['services']
    assert 'novnc' in data['services']


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
