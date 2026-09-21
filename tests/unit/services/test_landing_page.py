"""Unit tests for landing.py's page builders and request helpers.

The existing test_landing.py covers the leaf probes (check_port,
get_lan_ips, get_system_metrics). This file covers the HTML builders
and generate_landing_page — including the security-relevant branches:
forwarded-host XSS rejection, loopback-only VNC card under nginx, and
health card suppression behind the reverse proxy.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.services.landing as landing  # noqa: E402


@pytest.fixture
def fake_config(monkeypatch):
    """Deterministic config dict patched into landing._config()."""
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
    monkeypatch.setattr(landing, '_config', lambda: cfg)
    monkeypatch.setattr(landing, 'check_port', lambda *a, **k: False)
    monkeypatch.setattr(landing, 'get_lan_ips', lambda: [])
    return cfg


# ---------------------------------------------------------------------------
# _build_service_list
# ---------------------------------------------------------------------------

def test_service_list_core_services(fake_config):
    services = landing._build_service_list('http')
    names = [s['name'] for s in services]
    assert 'VNC Desktop (noVNC)' in names
    assert 'Web Terminal' in names
    assert 'Health Dashboard' in names


def test_service_list_urls_point_at_backend_ports(fake_config):
    services = landing._build_service_list('http')
    novnc = next(s for s in services if 'noVNC' in s['name'])
    assert novnc['url'] == 'http://127.0.0.1:6080/vnc.html'
    term = next(s for s in services if s['name'] == 'Web Terminal')
    assert term['url'] == 'http://127.0.0.1:7681/'


def test_service_list_external_base_uses_proxy_paths(fake_config):
    """Behind nginx the loopback ports are unreachable — cards must
    link the proxied paths, and health is suppressed (nginx restricts
    /health to loopback)."""
    services = landing._build_service_list(
        'https', external_base='https://example.com')
    novnc = next(s for s in services if 'noVNC' in s['name'])
    assert novnc['url'] == 'https://example.com/vnc/vnc.html'
    health = next(s for s in services if s['name'] == 'Health Dashboard')
    assert health['url'] == ''
    assert health['url2'] == ''


def test_service_list_audio_card_only_when_enabled(fake_config):
    services = landing._build_service_list('http')
    assert not any(s['name'] == 'Audio Stream' for s in services)
    fake_config['audio_stream_enabled'] = True
    services = landing._build_service_list('http')
    assert any(s['name'] == 'Audio Stream' for s in services)


def test_service_list_gamepad_card_only_when_enabled(fake_config):
    fake_config['gamepad_enabled'] = True
    services = landing._build_service_list('http')
    assert any(s['name'] == 'Gamepad Forwarding' for s in services)


def test_service_list_health_card_respects_flag(fake_config):
    fake_config['health_web_enabled'] = False
    services = landing._build_service_list('http')
    assert not any(s['name'] == 'Health Dashboard' for s in services)


# ---------------------------------------------------------------------------
# _build_service_cards_html
# ---------------------------------------------------------------------------

def test_cards_html_shows_online_offline(fake_config):
    services = [
        {'name': 'A', 'desc': 'd', 'features': [], 'icon': 'i',
         'url': 'http://x', 'port': 1, 'running': True,
         'color': '#000', 'category': 'c'},
        {'name': 'B', 'desc': 'd', 'features': [], 'icon': 'i',
         'url': 'http://y', 'port': 2, 'running': False,
         'color': '#000', 'category': 'c'},
    ]
    html = landing._build_service_cards_html(services)
    assert 'ONLINE' in html
    assert 'OFFLINE' in html
    assert 'disabled' in html


def test_cards_html_escapes_user_data(fake_config):
    services = [
        {'name': '<script>x</script>', 'desc': 'd', 'features': [],
         'icon': 'i', 'url': 'http://x', 'port': 1, 'running': True,
         'color': '#000', 'category': 'c'},
    ]
    html = landing._build_service_cards_html(services)
    assert '<script>x</script>' not in html or '&lt;script&gt;' in html


# ---------------------------------------------------------------------------
# _build_vnc_direct_html
# ---------------------------------------------------------------------------

def test_vnc_direct_nginx_shows_loopback(fake_config):
    fake_config['nginx_enabled'] = True
    monkeypatch_ips = ['192.168.1.50']
    html = landing._build_vnc_direct_html(monkeypatch_ips, True)
    assert '127.0.0.1:' in html
    assert '192.168.1.50:' not in html
    assert 'ONLINE' in html


def test_vnc_direct_no_nginx_shows_lan_ip(fake_config):
    html = landing._build_vnc_direct_html(['10.0.0.5'], False)
    assert '10.0.0.5:' in html
    assert 'OFFLINE' in html


# ---------------------------------------------------------------------------
# _build_metrics_html — escaping
# ---------------------------------------------------------------------------

def test_metrics_html_escapes_hostname(fake_config):
    metrics = {'hostname': '<img onerror=x>', 'os': 'OS', 'uptime': '1h',
               'cpu': '1%', 'memory': '2G', 'disk': '3G'}
    html = landing._build_metrics_html(metrics)
    assert '<img onerror' not in html
    assert '&lt;img' in html


# ---------------------------------------------------------------------------
# _build_lan_html
# ---------------------------------------------------------------------------

def test_lan_html_empty_when_no_ips(fake_config):
    assert landing._build_lan_html([], 'http') == ''


def test_lan_html_direct_links_without_nginx(fake_config):
    html = landing._build_lan_html(['10.0.0.5'], 'http')
    assert 'http://10.0.0.5:6080/vnc.html' in html
    assert 'http://10.0.0.5:7681/' in html


def test_lan_html_nginx_paths(fake_config):
    html = landing._build_lan_html(
        ['10.0.0.5'], 'https', external_base='https://gw')
    assert 'https://10.0.0.5/vnc/vnc.html' in html
    assert 'https://10.0.0.5/terminal/' in html


def test_lan_html_nginx_custom_port_suffix(fake_config):
    fake_config['nginx_https_port'] = 8443
    html = landing._build_lan_html(
        ['10.0.0.5'], 'https', external_base='https://gw')
    assert 'https://10.0.0.5:8443/vnc/vnc.html' in html


def test_lan_html_escapes_ip(fake_config):
    html = landing._build_lan_html(['<b>evil</b>'], 'http')
    assert '<b>evil</b>' not in html


# ---------------------------------------------------------------------------
# Static sections
# ---------------------------------------------------------------------------

def test_credentials_html_never_shows_passwords(fake_config):
    html = landing._build_credentials_html()
    assert '••••' in html
    assert '.env' in html


def test_features_section_ssl_only_when_https(fake_config):
    with_ssl = landing._build_features_section(True, False)
    without = landing._build_features_section(False, False)
    assert 'cifrada' in with_ssl.lower()
    assert 'cifrada' not in without.lower()


def test_firewall_html_linux_command(fake_config):
    fw, ssl_note = landing._build_firewall_html(False, False)
    assert 'ufw allow 8000' in fw
    assert ssl_note == ''


def test_firewall_html_windows_command(fake_config):
    fw, _ = landing._build_firewall_html(True, False)
    assert 'New-NetFirewallRule' in fw
    assert '8000' in fw


def test_ssl_note_present_when_ssl(fake_config):
    _, ssl_note = landing._build_firewall_html(False, True)
    assert 'Self-signed' in ssl_note


def test_landing_css_returns_style_block(fake_config):
    css = landing._landing_css()
    assert '<style>' in css


# ---------------------------------------------------------------------------
# generate_landing_page
# ---------------------------------------------------------------------------

def test_generate_landing_page_assembles(fake_config, monkeypatch):
    monkeypatch.setattr(
        landing, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    page = landing.generate_landing_page()
    assert 'VNC Remote Secure' in page
    assert 'Servicios Disponibles' in page


def test_generate_landing_page_rejects_evil_forwarded_host(
        fake_config, monkeypatch):
    """A crafted X-Forwarded-Host containing markup must not be
    reflected into the rendered page (XSS via nginx $host)."""
    monkeypatch.setattr(
        landing, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    evil = 'x.com"><script>alert(1)</script>'
    page = landing.generate_landing_page(
        forwarded_host=evil, forwarded_proto='https')
    assert evil not in page


def test_generate_landing_page_accepts_valid_forwarded_host(
        fake_config, monkeypatch):
    monkeypatch.setattr(
        landing, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    page = landing.generate_landing_page(
        forwarded_host='desk.example.com', forwarded_proto='https')
    assert 'https://desk.example.com/vnc/vnc.html' in page
