"""Unit tests for security.posture — the posture score must reflect
real env state: TLS off drops the score, MFA on raises it, weak creds
are flagged."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security import posture  # noqa: E402

_STRONG = 'Str0ng!Pass'

ENV_KEYS = ('TLS_ENABLED', 'DISABLE_SSL', 'SSL_CERT', 'SSL_KEY',
            'MFA_REQUIRED', 'TOTP_SECRET', 'VNC_PASSWORD',
            'TTYD_PASSWD', 'USER_UI_PASSWORD', 'LANDING_PASSWORD',
            'BIND_HOST', 'BACKEND_BIND_HOST', 'KEEP_TEMP_USER',
            'SESSION_IDLE_TIMEOUT', 'SESSION_MAX_LIFETIME')

_STRONG_CREDS = {'VNC_PASSWORD': _STRONG, 'TTYD_PASSWD': _STRONG,
                 'USER_UI_PASSWORD': _STRONG, 'LANDING_PASSWORD': _STRONG}


def _by_name(result):
    return {f['name']: f for f in result['checks']}


def test_posture_shape():
    r = posture.calculate_posture()
    assert 'score' in r
    assert 'checks' in r
    assert 0 <= r['score'] <= 100


def test_tls_off_lowers_score(clear_env):
    clear_env(*ENV_KEYS, set={
        'TLS_ENABLED': 'false', 'DISABLE_SSL': 'true', **_STRONG_CREDS})
    r = posture.calculate_posture()
    f = _by_name(r)
    assert f['HTTPS/TLS enabled']['status'] != 'ok'


def test_mfa_and_strong_creds_raise_score(clear_env):
    clear_env(*ENV_KEYS, set={
        'TLS_ENABLED': 'true', 'MFA_REQUIRED': 'true', **_STRONG_CREDS})
    r = posture.calculate_posture()
    f = _by_name(r)
    assert f['MFA enabled']['status'] == 'ok'
    assert f['Strong credentials configured']['status'] == 'ok'


def test_weak_password_flagged(clear_env):
    clear_env(*ENV_KEYS, set={
        'TLS_ENABLED': 'true', 'VNC_PASSWORD': 'changeme',
        **{k: v for k, v in _STRONG_CREDS.items() if k != 'VNC_PASSWORD'}})
    r = posture.calculate_posture()
    f = _by_name(r)
    assert f['Strong credentials configured']['status'] != 'ok'


def test_generated_credentials_count(monkeypatch, clear_env):
    """Env unset but generated credential persisted -> strong."""
    clear_env(*ENV_KEYS, set={'TLS_ENABLED': 'true'})
    monkeypatch.setattr(
        'vnc_remote_secure.core.config._load_generated_credential',
        lambda n: _STRONG, raising=False)
    r = posture.calculate_posture()
    f = _by_name(r)
    assert f['Strong credentials configured']['status'] == 'ok'


def test_no_credentials_flagged(monkeypatch, clear_env):
    clear_env(*ENV_KEYS, set={'TLS_ENABLED': 'true'})
    monkeypatch.setattr(
        'vnc_remote_secure.core.config._load_generated_credential',
        lambda n: '', raising=False)
    r = posture.calculate_posture()
    f = _by_name(r)
    assert f['Strong credentials configured']['status'] != 'ok'
