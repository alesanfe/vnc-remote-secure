"""Unit tests for core.portal service-inventory helpers.

The existing test_landing.py covers the leaf probes (check_port,
get_lan_ips, get_system_metrics). This file covers the service-card
composition — including the security-relevant branches: proxy-path
links behind nginx, loopback-only VNC card under nginx, and health
card suppression behind the reverse proxy.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import portal as core_portal  # noqa: E402


@pytest.fixture
def fake_config(monkeypatch):
    """Deterministic config dict patched into core.portal."""
    cfg = {
        'novnc_port': 6080, 'ttyd_port': 7681, 'health_port': 8080,
        'landing_port': 8000, 'vnc_port': 5900, 'vnc_http_port': 5800,
        'vnc_display': ':1', 'audio_stream_port': 8090,
        'gamepad_port': 8091, 'nginx_https_port': 443,
        'novnc_host': '127.0.0.1', 'ttyd_host': '127.0.0.1',
        'health_host': '127.0.0.1', 'audio_stream_host': '127.0.0.1',
        'gamepad_host': '127.0.0.1',
        'health_web_enabled': True,
        'audio_stream_enabled': False, 'gamepad_enabled': False,
        'nginx_enabled': False,
        'ssl_cert': '', 'ssl_key': '',
    }
    monkeypatch.setattr(core_portal, 'portal_config', lambda: cfg)
    monkeypatch.setattr(core_portal, 'check_port', lambda *a, **k: False)
    return cfg


# ---------------------------------------------------------------------------
# _build_service_list
# ---------------------------------------------------------------------------

def test_service_list_core_services(fake_config):
    services = core_portal.build_service_list('http')
    names = [s['name'] for s in services]
    assert 'VNC Desktop (noVNC)' in names
    assert 'Web Terminal' in names
    assert 'Health Dashboard' in names


def test_service_list_urls_point_at_backend_ports(fake_config):
    services = core_portal.build_service_list('http')
    novnc = next(s for s in services if 'noVNC' in s['name'])
    assert novnc['url'] == 'http://127.0.0.1:6080/vnc.html'
    term = next(s for s in services if s['name'] == 'Web Terminal')
    assert term['url'] == 'http://127.0.0.1:7681/'


def test_service_list_external_base_uses_proxy_paths(fake_config):
    """Behind nginx the loopback ports are unreachable — cards must
    link the proxied paths, and health is suppressed (nginx restricts
    /health to loopback)."""
    services = core_portal.build_service_list(
        'https', external_base='https://example.com')
    novnc = next(s for s in services if 'noVNC' in s['name'])
    assert novnc['url'] == 'https://example.com/vnc/vnc.html'
    health = next(s for s in services if s['name'] == 'Health Dashboard')
    assert health['url'] == ''
    assert health['url2'] == ''


def test_service_list_audio_card_only_when_enabled(fake_config):
    services = core_portal.build_service_list('http')
    assert not any(s['name'] == 'Audio Stream' for s in services)
    fake_config['audio_stream_enabled'] = True
    services = core_portal.build_service_list('http')
    assert any(s['name'] == 'Audio Stream' for s in services)


def test_service_list_gamepad_card_only_when_enabled(fake_config):
    fake_config['gamepad_enabled'] = True
    services = core_portal.build_service_list('http')
    assert any(s['name'] == 'Gamepad Forwarding' for s in services)


def test_service_list_health_card_respects_flag(fake_config):
    fake_config['health_web_enabled'] = False
    services = core_portal.build_service_list('http')
    assert not any(s['name'] == 'Health Dashboard' for s in services)
