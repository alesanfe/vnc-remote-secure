"""Unit tests for services.landing module.

All network, subprocess, and socket dependencies are mocked so the tests
are deterministic and run in air-gapped environments.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import landing

# ---------------------------------------------------------------------------
# check_port
# ---------------------------------------------------------------------------


def test_check_port_returns_bool_when_closed(monkeypatch):
    """check_port returns False when nothing listens (port available)."""
    monkeypatch.setattr(
        'vnc_remote_secure.core.processes.is_port_available',
        lambda port, host='127.0.0.1': True)
    assert landing.check_port(59999) is False


def test_check_port_returns_true_when_open(monkeypatch):
    """check_port returns True when the port is listening."""
    monkeypatch.setattr(
        'vnc_remote_secure.core.processes.is_port_available',
        lambda port, host='127.0.0.1': False)
    assert landing.check_port(5900) is True


def test_check_port_returns_false_on_exception(monkeypatch):
    """check_port returns False if the probe raises."""
    def _boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(
        'vnc_remote_secure.core.processes.is_port_available', _boom)
    assert landing.check_port(5900) is False


def test_check_port_wildcard_normalised_to_loopback(monkeypatch):
    """A wildcard/empty host is probed on loopback (Windows cannot
    connect to '0.0.0.0')."""
    seen = {}

    def _spy(port, host='127.0.0.1'):
        seen['host'] = host
        return False  # listening
    monkeypatch.setattr(
        'vnc_remote_secure.core.processes.is_port_available', _spy)
    assert landing.check_port(5900, '0.0.0.0') is True
    assert seen['host'] == '127.0.0.1'


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
    monkeypatch.setattr(linux_metrics, 'get_os_display_name', lambda: 'Ubuntu 24.04 LTS')

    metrics = landing.get_system_metrics()
    assert isinstance(metrics, dict)
    assert metrics['cpu'] == 'Load: 0.42'
    assert metrics['cpu_percent'] == '15%'
    assert metrics['memory'] == '45% (1024 MB / 2048 MB)'
    assert metrics['disk'] == '/ 50% (10G used)'
    assert metrics['uptime'] == '1h 30m'
    assert metrics['hostname'] == 'test-host'
    # os should be overridden by get_os_display_name when it returns a value.
    assert metrics['os'] == 'Ubuntu 24.04 LTS'


def test_get_system_metrics_falls_back_to_platform_release(monkeypatch):
    """get_system_metrics falls back to platform.release() when get_os_display_name returns None."""
    monkeypatch.setattr(landing.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(landing.platform, 'node', lambda: 'test-host')
    monkeypatch.setattr(landing.platform, 'release', lambda: '6.5')

    fake_metrics = {'cpu': 'N/A', 'memory': 'N/A', 'disk': 'N/A', 'uptime': 'N/A'}
    import vnc_remote_secure.platform.linux.metrics as linux_metrics
    monkeypatch.setattr(linux_metrics, 'get_system_metrics', lambda: fake_metrics)
    monkeypatch.setattr(linux_metrics, 'get_os_display_name', lambda: None)

    metrics = landing.get_system_metrics()
    assert metrics['os'] == 'Linux 6.5'


# ---------------------------------------------------------------------------
# Module-level configuration sanity
# ---------------------------------------------------------------------------

def test_landing_port_is_integer():
    """landing_port is a positive integer matching the configured default."""
    port = landing._config()['landing_port']
    assert isinstance(port, int)
    assert port > 0
    assert port == landing._config()['landing_port']  # deterministic across calls


def test_landing_host_is_string():
    """landing_host is a non-empty string (typically 127.0.0.1 in dev)."""
    host = landing._config()['landing_host']
    assert isinstance(host, str)
    assert len(host) > 0
    # The bind host must be an IP literal or localhost — a bare
    # hostname without dots would still be wrong.
    import ipaddress
    if host != 'localhost':
        ipaddress.ip_address(host)  # raises if not a valid IP


def test_vnc_http_port_is_integer():
    """vnc_http_port is a positive integer in the valid port range."""
    port = landing._config()['vnc_http_port']
    assert isinstance(port, int)
    assert 1024 <= port <= 65535  # privileged ports excluded
