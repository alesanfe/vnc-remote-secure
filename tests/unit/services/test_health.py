"""Unit tests for services.health module.

`is_port_available` is mocked so the tests are deterministic and do not
depend on which ports happen to be listening on the host.
"""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import health


# ---------------------------------------------------------------------------
# check_health
# ---------------------------------------------------------------------------

def test_check_health_returns_dict(monkeypatch):
    """check_health returns a dict mapping known service names to booleans."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    status = health.check_health()
    assert isinstance(status, dict)
    expected_services = {'vnc', 'novnc', 'ttyd', 'health', 'landing'}
    assert set(status.keys()) == expected_services
    assert all(isinstance(v, bool) for v in status.values())


def test_check_health_has_vnc_entry(monkeypatch):
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    assert 'vnc' in health.check_health()


def test_check_health_values_are_bool_when_all_down(monkeypatch):
    """When all ports are available (no service listening), all are False."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    status = health.check_health()
    for name, listening in status.items():
        assert isinstance(listening, bool), f"{name} should be bool"
        assert listening is False


def test_check_health_values_are_bool_when_all_up(monkeypatch):
    """When no port is available (all services listening), all are True."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: False)
    status = health.check_health()
    for name, listening in status.items():
        assert listening is True


# ---------------------------------------------------------------------------
# get_health_status
# ---------------------------------------------------------------------------

def test_get_health_status_returns_dict(monkeypatch):
    """get_health_status returns a dict with all expected fields."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    result = health.get_health_status()
    assert isinstance(result, dict)
    assert set(result.keys()) == {'status', 'services_up', 'services_total', 'services'}
    assert isinstance(result['services'], dict)


def test_get_health_status_has_status_field(monkeypatch):
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    result = health.get_health_status()
    assert 'status' in result
    assert result['status'] in ('healthy', 'degraded', 'down', 'unknown')


def test_get_health_status_has_counts(monkeypatch):
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    result = health.get_health_status()
    assert 'services_up' in result
    assert 'services_total' in result
    assert isinstance(result['services_up'], int)
    assert isinstance(result['services_total'], int)


def test_get_health_status_healthy_when_all_up(monkeypatch):
    """All services listening -> status 'healthy'."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: False)
    result = health.get_health_status()
    assert result['status'] == 'healthy'
    assert result['services_up'] == result['services_total']


def test_get_health_status_down_when_all_down(monkeypatch):
    """No services listening -> status 'down'."""
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)
    result = health.get_health_status()
    assert result['status'] == 'down'
    assert result['services_up'] == 0


def test_get_health_status_degraded_when_partial(monkeypatch):
    """Some services up, some down -> status 'degraded'."""
    up_ports = {5901, 6080}  # vnc + novnc listening
    def _fake(port):
        return port not in up_ports
    monkeypatch.setattr(health, 'is_port_available', _fake)
    result = health.get_health_status()
    assert result['status'] == 'degraded'
    assert 0 < result['services_up'] < result['services_total']


# ---------------------------------------------------------------------------
# start_health_server (smoke test with real socket on ephemeral port)
# ---------------------------------------------------------------------------

def test_start_health_server_serves_json(monkeypatch):
    """start_health_server returns a server that serves /health JSON.

    When all services are down, /health returns 503 (Service Unavailable)
    per the readiness contract. When healthy or degraded, returns 200.
    """
    import http.client
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)

    server = health.start_health_server(port=0, host='127.0.0.1')
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection('127.0.0.1', actual_port, timeout=5)
        conn.request('GET', '/health')
        resp = conn.getresponse()
        body = resp.read().decode()
        data = json.loads(body)
        assert 'status' in data
        assert data['status'] in ('healthy', 'degraded', 'down', 'unknown')
        # 503 when down, 200 when healthy/degraded
        if data['status'] == 'down':
            assert resp.status == 503
        else:
            assert resp.status == 200
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_start_health_server_serves_health_all(monkeypatch):
    """start_health_server serves /health/all with the documented contract."""
    import http.client
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)

    server = health.start_health_server(port=0, host='127.0.0.1')
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection('127.0.0.1', actual_port, timeout=5)
        conn.request('GET', '/health/all')
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode()
        data = json.loads(body)
        # Documented contract: system + services object with status/up/total
        assert 'system' in data
        assert 'services' in data
        assert 'status' in data['services']
        assert 'services_up' in data['services']
        assert 'services_total' in data['services']
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_start_health_server_health_all_returns_500_on_failure(monkeypatch):
    """/health/all returns a JSON 500 envelope when get_all_health raises."""
    import http.client
    monkeypatch.setattr(health, 'is_port_available', lambda port: True)

    # Force get_all_health to raise
    def _boom():
        raise RuntimeError("metrics unavailable")
    import vnc_remote_secure.monitoring.health as monitoring_health
    monkeypatch.setattr(monitoring_health, 'get_all_health', _boom)

    server = health.start_health_server(port=0, host='127.0.0.1')
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection('127.0.0.1', actual_port, timeout=5)
        conn.request('GET', '/health/all')
        resp = conn.getresponse()
        assert resp.status == 500
        body = resp.read().decode()
        data = json.loads(body)
        assert data.get('error') is True
        assert 'message' in data
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
