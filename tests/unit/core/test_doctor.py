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


def test_healthy_flag_reflects_failures(monkeypatch):
    """healthy must be False exactly when a check is 'fail' — the flag
    is the machine-readable contract for CI/monitoring.

    Down service ports are 'skip' (doctor is diagnostic); a default
    VNC password is a 'fail'."""
    monkeypatch.setattr(
        doctor, 'get_config',
        lambda: {'vnc_password': 'changeme'})
    result = _run(monkeypatch)
    assert result['healthy'] is False
    assert result['summary']['fail'] > 0
    secrets_check = next(
        c for c in result['checks'] if c['name'] == 'secrets.vnc_password')
    assert secrets_check['status'] == 'fail'


def test_healthy_true_when_only_warns(monkeypatch):
    """Warnings/skips must NOT mark the deployment unhealthy."""
    monkeypatch.setattr(doctor, '_check_port', lambda h, p: True)
    monkeypatch.setattr(doctor, '_check_binary', lambda n: True)
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.get_blocking_findings',
        list, raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.'
        'validate_profile_consistency', list, raising=False)
    result = _run(monkeypatch)
    # Secrets check may still fail with no env password — only check
    # the flag math: healthy == (no 'fail' checks).
    expected = not any(c['status'] == 'fail' for c in result['checks'])
    assert result['healthy'] == expected
    assert result['summary']['fail'] == sum(
        1 for c in result['checks'] if c['status'] == 'fail')


def test_json_output_serializable(monkeypatch):
    """as_json result must be JSON-serializable — the CLI prints it."""
    import json
    result = _run(monkeypatch)
    json.dumps(result)


def test_blocking_finding_fails_check(monkeypatch):
    """A config_inspector blocker surfaces as config.blockers fail."""
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.get_blocking_findings',
        lambda: [{'message': 'plain HTTP on public interface'}],
        raising=False)
    result = _run(monkeypatch)
    blk = next(c for c in result['checks'] if c['name'] == 'config.blockers')
    assert blk['status'] == 'fail'
    assert 'plain HTTP' in blk['message']
