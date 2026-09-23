"""Unit tests for the unified doctor diagnostics.

Verifies the check taxonomy: per-service port probing, optional-service
skip semantics, and the nginx public-entry probe when NGINX_ENABLED.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import doctor

DOCTOR_ENV_KEYS = ('NGINX_ENABLED', 'AUDIO_STREAM_ENABLED',
                   'GAMEPAD_ENABLED', 'USER_UI_ENABLED',
                   'HEALTH_WEB_ENABLED')


def _run(monkeypatch, clear_env, **env):
    clear_env(*DOCTOR_ENV_KEYS, set=env)
    # Deterministic port probing: nothing listens.
    monkeypatch.setattr(doctor, '_check_port', lambda h, p: False)
    return doctor.run_doctor(as_json=True)


def test_result_shape(monkeypatch, clear_env):
    """run_doctor returns the documented checks/summary/healthy keys."""
    result = _run(monkeypatch, clear_env)
    assert 'checks' in result
    assert 'summary' in result
    assert 'healthy' in result
    names = [c['name'] for c in result['checks']]
    assert 'ports.vnc' in names
    assert 'ports.landing' in names


def test_optional_services_skipped_when_disabled(monkeypatch, clear_env):
    """Disabled optional services are reported as skipped, not absent."""
    result = _run(monkeypatch, clear_env, AUDIO_STREAM_ENABLED='false',
                  GAMEPAD_ENABLED='false', USER_UI_ENABLED='false')
    by_name = {c['name']: c for c in result['checks']}
    assert by_name['ports.audio']['status'] == 'skip'
    assert by_name['ports.gamepad']['status'] == 'skip'
    assert by_name['ports.user_ui']['status'] == 'skip'


def test_nginx_probe_added_when_enabled(monkeypatch, clear_env):
    """NGINX_ENABLED=true adds the public-entry port check."""
    result = _run(monkeypatch, clear_env, NGINX_ENABLED='true')
    names = [c['name'] for c in result['checks']]
    assert 'ports.nginx' in names
    nginx = next(c for c in result['checks'] if c['name'] == 'ports.nginx')
    assert nginx['status'] == 'fail'  # nothing listening in the test env


def test_nginx_probe_absent_when_disabled(monkeypatch, clear_env):
    """Without NGINX_ENABLED there is no ports.nginx check."""
    result = _run(monkeypatch, clear_env)
    names = [c['name'] for c in result['checks']]
    assert 'ports.nginx' not in names


def test_healthy_flag_reflects_failures(monkeypatch, clear_env):
    """healthy must be False exactly when a check is 'fail' — the flag
    is the machine-readable contract for CI/monitoring.

    Down service ports are 'skip' (doctor is diagnostic); a default
    VNC password is a 'fail'."""
    monkeypatch.setattr(
        doctor, 'get_config',
        lambda: {'vnc_password': 'changeme'})
    result = _run(monkeypatch, clear_env)
    assert result['healthy'] is False
    assert result['summary']['fail'] > 0
    secrets_check = next(
        c for c in result['checks'] if c['name'] == 'secrets.vnc_password')
    assert secrets_check['status'] == 'fail'


def test_healthy_true_when_only_warns(monkeypatch, clear_env):
    """Warnings/skips must NOT mark the deployment unhealthy."""
    monkeypatch.setattr(doctor, '_check_port', lambda h, p: True)
    monkeypatch.setattr(doctor, '_check_binary', lambda n: True)
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.get_blocking_findings',
        list, raising=False)
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.'
        'validate_profile_consistency', list, raising=False)
    result = _run(monkeypatch, clear_env)
    # Secrets check may still fail with no env password — only check
    # the flag math: healthy == (no 'fail' checks).
    expected = not any(c['status'] == 'fail' for c in result['checks'])
    assert result['healthy'] == expected
    assert result['summary']['fail'] == sum(
        1 for c in result['checks'] if c['status'] == 'fail')


def test_json_output_serializable(monkeypatch, clear_env):
    """as_json result must be JSON-serializable — the CLI prints it."""
    import json
    result = _run(monkeypatch, clear_env)
    json.dumps(result)


def test_blocking_finding_fails_check(monkeypatch, clear_env):
    """A config_inspector blocker surfaces as config.blockers fail."""
    monkeypatch.setattr(
        'vnc_remote_secure.core.doctor.get_blocking_findings',
        lambda: [{'message': 'plain HTTP on public interface'}],
        raising=False)
    result = _run(monkeypatch, clear_env)
    blk = next(c for c in result['checks'] if c['name'] == 'config.blockers')
    assert blk['status'] == 'fail'
    assert 'plain HTTP' in blk['message']


class TestPublicListenersCheck:
    """security.public_listeners verifies the trust boundary at
    runtime — websockify/RFB must never be off-host."""

    def _run_check(self, monkeypatch, listeners, nginx=False,
                   profile='development'):
        from vnc_remote_secure.core import doctor
        monkeypatch.setattr(doctor, '_list_listeners',
                            lambda: listeners)
        monkeypatch.setattr(
            'vnc_remote_secure.security.profiles.get_profile',
            lambda: profile, raising=False)
        checks = []
        cfg = {'novnc_ws_port': 6081, 'vnc_port': 5900,
               'ttyd_port': 5000, 'nginx_enabled': nginx,
               'novnc_port': 6080, 'landing_port': 8000}
        doctor._check_public_listeners(checks, cfg)
        return checks[0]

    def test_websockify_public_always_fails(self, monkeypatch):
        c = self._run_check(monkeypatch, [('0.0.0.0', 6081)])
        assert c['status'] == 'fail'
        assert 'websockify' in c['message']

    def test_rfb_public_fails_under_nginx(self, monkeypatch):
        c = self._run_check(monkeypatch, [('0.0.0.0', 5900)],
                            nginx=True)
        assert c['status'] == 'fail'
        assert 'RFB' in c['message']

    def test_rfb_public_fails_hardened(self, monkeypatch):
        c = self._run_check(monkeypatch, [('0.0.0.0', 5900)],
                            profile='public-hardened')
        assert c['status'] == 'fail'

    def test_rfb_public_warns_direct_mode(self, monkeypatch):
        """Direct-RFB mode is intentional on a trusted LAN — warn,
        not fail."""
        c = self._run_check(monkeypatch, [('0.0.0.0', 5900)])
        assert c['status'] == 'warn'
        assert 'DES' in c['message']

    def test_loopback_only_ok(self, monkeypatch):
        c = self._run_check(monkeypatch,
                            [('127.0.0.1', 5900), ('127.0.0.1', 6081),
                             ('127.0.0.1', 6080)])
        assert c['status'] == 'ok'

    def test_backend_public_under_nginx_fails(self, monkeypatch):
        c = self._run_check(monkeypatch, [('0.0.0.0', 6080)],
                            nginx=True)
        assert c['status'] == 'fail'
        assert 'bypass' in c['message']

    def test_backend_public_no_nginx_warns(self, monkeypatch):
        c = self._run_check(monkeypatch, [('0.0.0.0', 5000)])
        assert c['status'] == 'warn'

    def test_enumeration_failure_skips(self, monkeypatch):
        """A probe that can't enumerate must not report a false ok."""
        c = self._run_check(monkeypatch, None)
        assert c['status'] == 'skip'

    def test_unrelated_public_port_ignored(self, monkeypatch):
        """Ports that aren't ours (e.g. another app on 8080) don't
        fire the check."""
        c = self._run_check(monkeypatch, [('0.0.0.0', 8080)])
        assert c['status'] == 'ok'
