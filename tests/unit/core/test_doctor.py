"""Unit tests for the unified doctor diagnostics.

Verifies the check taxonomy: per-service port probing, optional-service
skip semantics, and the nginx public-entry probe when NGINX_ENABLED.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import doctor


def _run(monkeypatch, **env):
    for key in ('NGINX_ENABLED', 'AUDIO_STREAM_ENABLED',
                'GAMEPAD_ENABLED', 'USER_UI_ENABLED',
                'HEALTH_WEB_ENABLED'):
        monkeypatch.delenv(key, raising=False)
    for key, val in env.items():
        monkeypatch.setenv(key, val)
    # Deterministic port probing: nothing listens.
    monkeypatch.setattr(doctor, '_check_port', lambda h, p: False)
    return doctor.run_doctor(as_json=True)


def test_result_shape(monkeypatch):
    """run_doctor returns the documented checks/summary/healthy keys."""
    result = _run(monkeypatch)
    assert 'checks' in result
    assert 'summary' in result
    assert 'healthy' in result
    names = [c['name'] for c in result['checks']]
    assert 'ports.vnc' in names
    assert 'ports.landing' in names


def test_optional_services_skipped_when_disabled(monkeypatch):
    """Disabled optional services are reported as skipped, not absent."""
    result = _run(monkeypatch, AUDIO_STREAM_ENABLED='false',
                  GAMEPAD_ENABLED='false', USER_UI_ENABLED='false')
    by_name = {c['name']: c for c in result['checks']}
    assert by_name['ports.audio']['status'] == 'skip'
    assert by_name['ports.gamepad']['status'] == 'skip'
    assert by_name['ports.user_ui']['status'] == 'skip'


def test_nginx_probe_added_when_enabled(monkeypatch):
    """NGINX_ENABLED=true adds the public-entry port check."""
    result = _run(monkeypatch, NGINX_ENABLED='true')
    names = [c['name'] for c in result['checks']]
    assert 'ports.nginx' in names
    nginx = next(c for c in result['checks'] if c['name'] == 'ports.nginx')
    assert nginx['status'] == 'fail'  # nothing listening in the test env


def test_nginx_probe_absent_when_disabled(monkeypatch):
    """Without NGINX_ENABLED there is no ports.nginx check."""
    result = _run(monkeypatch)
    names = [c['name'] for c in result['checks']]
    assert 'ports.nginx' not in names
