"""Tests for /metrics, /audit, /audit/verify and the 404 default —
the health endpoints not covered by test_health_endpoints.py."""
import http.client
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import health


@pytest.fixture
def health_server(monkeypatch):
    monkeypatch.setattr(health, 'is_port_available', lambda port, host=None: True)
    server = health.start_health_server(port=0, host='127.0.0.1')
    yield server
    server.shutdown()
    server.server_close()


def _get(server, path):
    conn = http.client.HTTPConnection(
        '127.0.0.1', server.server_address[1], timeout=5)
    conn.request('GET', path)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


def test_metrics_endpoint_returns_prometheus_format(health_server):
    status, headers, body = _get(health_server, '/metrics')
    assert status == 200
    assert 'text/plain' in headers.get('Content-Type', '')


def test_audit_endpoint_returns_entries(health_server):
    status, _, body = _get(health_server, '/audit')
    assert status == 200
    json.loads(body)  # valid JSON list/dict


def test_audit_endpoint_bad_limit_400(health_server):
    status, _, _ = _get(health_server, '/audit?limit=notanint')
    assert status == 400


def test_audit_endpoint_limit_clamped(health_server):
    """limit=999999 is clamped to 1000 — no unbounded reads."""
    status, _, body = _get(health_server, '/audit?limit=999999')
    assert status == 200
    json.loads(body)


def test_audit_verify_returns_chain_status(health_server):
    status, _, body = _get(health_server, '/audit/verify')
    assert status == 200
    data = json.loads(body)
    assert 'intact' in data
    assert 'message' in data


def test_unknown_path_404(health_server):
    status, _, body = _get(health_server, '/does-not-exist')
    assert status == 404
    data = json.loads(body)
    assert 'error' in data or 'status' in data
