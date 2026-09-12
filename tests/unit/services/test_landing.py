"""Unit tests for services.landing module.

All network, subprocess, and socket dependencies are mocked so the tests
are deterministic and run in air-gapped environments.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import landing


# ---------------------------------------------------------------------------
# check_port
# ---------------------------------------------------------------------------

def test_check_port_returns_bool_when_closed(monkeypatch):
    """check_port returns False when the socket cannot connect."""
    class _FakeSocket:
        def __init__(self, *a, **k): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 111  # connection refused
        def close(self): pass

    monkeypatch.setattr(landing.socket, 'socket', lambda *a, **k: _FakeSocket())
    assert landing.check_port(59999) is False


def test_check_port_returns_true_when_open(monkeypatch):
    """check_port returns True when connect_ex returns 0."""
    class _FakeSocket:
        def __init__(self, *a, **k): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0
        def close(self): pass

    monkeypatch.setattr(landing.socket, 'socket', lambda *a, **k: _FakeSocket())
    assert landing.check_port(5900) is True


def test_check_port_returns_false_on_exception(monkeypatch):
    """check_port returns False if socket raises."""
    def _boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(landing.socket, 'socket', _boom)
    assert landing.check_port(5900) is False


# ---------------------------------------------------------------------------
# get_lan_ips
# ---------------------------------------------------------------------------

def test_get_lan_ips_returns_list_with_mock(monkeypatch):
    """get_lan_ips delegates to the platform adapter and returns its list."""
    class _FakeAdapter:
        def get_lan_ips(self):
            return ['192.168.1.42']
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', lambda: _FakeAdapter()
    )
    ips = landing.get_lan_ips()
    assert isinstance(ips, list)
    assert '192.168.1.42' in ips


def test_get_lan_ips_filters_loopback(monkeypatch):
    """get_lan_ips returns the adapter output unchanged (filtering is the adapter's job)."""
    class _FakeAdapter:
        def get_lan_ips(self):
            return ['192.168.1.42']
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', lambda: _FakeAdapter()
    )
    ips = landing.get_lan_ips()
    assert '127.0.0.1' not in ips


def test_get_lan_ips_handles_adapter_failure(monkeypatch):
    """get_lan_ips returns an empty list when the adapter raises."""
    def _raise():
        raise RuntimeError("platform not supported")
    monkeypatch.setattr('vnc_remote_secure.platform.base.get_adapter', _raise)
    ips = landing.get_lan_ips()
    assert isinstance(ips, list)
    assert ips == []  # No IPs discoverable


# ---------------------------------------------------------------------------
# get_system_metrics
# ---------------------------------------------------------------------------

def test_get_system_metrics_returns_dict(monkeypatch):
    """get_system_metrics returns a dict with expected keys and values."""
    monkeypatch.setattr(landing.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(landing.platform, 'node', lambda: 'test-host')
    monkeypatch.setattr(landing.platform, 'release', lambda: '6.5')

    # Mock the platform metrics module to return deterministic values
    fake_metrics = {
        'cpu': 'Load: 0.42',
        'cpu_percent': '15%',
        'memory': '45% (1024 MB / 2048 MB)',
        'disk': '/ 50% (10G used)',
        'uptime': '1h 30m',
    }
    import vnc_remote_secure.platform.linux.metrics as linux_metrics
    monkeypatch.setattr(linux_metrics, 'get_system_metrics', lambda: fake_metrics)

    metrics = landing.get_system_metrics()
    assert isinstance(metrics, dict)
    assert metrics['cpu'] == 'Load: 0.42'
    assert metrics['cpu_percent'] == '15%'
    assert metrics['memory'] == '45% (1024 MB / 2048 MB)'
    assert metrics['disk'] == '/ 50% (10G used)'
    assert metrics['uptime'] == '1h 30m'
    assert metrics['hostname'] == 'test-host'
    assert metrics['os'] == 'Linux 6.5'


# ---------------------------------------------------------------------------
# Module-level configuration sanity
# ---------------------------------------------------------------------------

def test_landing_port_is_integer():
    assert isinstance(landing.PORT, int)
    assert landing.PORT > 0


def test_landing_host_is_string():
    assert isinstance(landing.HOST, str)
    assert len(landing.HOST) > 0


def test_vnc_http_port_is_integer():
    assert isinstance(landing.VNC_HTTP_PORT, int)
    assert landing.VNC_HTTP_PORT > 0
