"""Unit tests for monitoring.health — system/service aggregation."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.monitoring import health


def test_get_system_health_shape(monkeypatch):
    monkeypatch.setattr(health, '_get_platform_metrics',
                        lambda: {'cpu': '1%', 'memory': '2%'})
    h = health.get_system_health()
    for k in ('cpu', 'memory', 'disk', 'uptime', 'hostname', 'os'):
        assert k in h
    assert h['cpu'] == '1%'


def test_platform_metrics_failure_na(monkeypatch):
    """Adapter metrics failure must degrade to N/A, not crash —
    a WMI/proc error is exactly what the health endpoint exists to
    report on, so it must not take the endpoint down."""
    monkeypatch.setattr(
        'vnc_remote_secure.platform.windows.metrics.get_system_metrics',
        lambda: (_ for _ in ()).throw(RuntimeError('wmi down')),
        raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.platform.linux.metrics.get_system_metrics',
        lambda: (_ for _ in ()).throw(RuntimeError('proc unreadable')),
        raising=False)
    h = health.get_system_health()
    assert h['cpu'] == 'N/A'
    assert h['memory'] == 'N/A'


def test_get_service_health_single(monkeypatch):
    monkeypatch.setattr(
        health, 'get_health_status',
        lambda: {'services': {'vnc': True, 'novnc': False}})
    assert health.get_service_health('vnc') == {'vnc': True}
    assert health.get_service_health('missing') == {'missing': False}


def test_get_service_health_all(monkeypatch):
    monkeypatch.setattr(
        health, 'get_health_status',
        lambda: {'services': {'vnc': True}})
    assert health.get_service_health() == {'vnc': True}


def test_get_all_health_posture_failure_safe(monkeypatch):
    """calculate_posture raising must not break the endpoint."""
    monkeypatch.setattr(
        health, 'get_health_status',
        lambda: {'status': 'ok', 'services': {}})
    monkeypatch.setattr(
        'vnc_remote_secure.security.posture.calculate_posture',
        lambda: (_ for _ in ()).throw(RuntimeError('x')), raising=False)
    h = health.get_all_health()
    assert h['posture'] == {}
    assert h['services']['status'] == 'ok'
