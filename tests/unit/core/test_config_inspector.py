"""Unit tests for core.config_inspector — validate_config checks.

Each check is exercised on the exact boundary: critical findings must
fire one step outside the valid range and stay quiet one step inside.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core.config_inspector import (  # noqa: E402
    compute_effective_config,
    validate_config,
)


def _find(env, profile='development'):
    return validate_config(env_snapshot=env, profile_name=profile)


def _critical(findings):
    return [f for f in findings if f['severity'] == 'critical']


class TestBackendBindHost:
    def test_public_bind_critical(self):
        f = _find({'BACKEND_BIND_HOST': '0.0.0.0'})
        assert any('BACKEND_BIND_HOST' in x['message'] for x in _critical(f))

    def test_loopback_ok(self):
        f = _find({'BACKEND_BIND_HOST': '127.0.0.1'})
        assert not any(
            'BACKEND_BIND_HOST' in x['message'] for x in _critical(f))


class TestLockedVars:
    """Hardened profiles lock security vars — the lock IS the control;
    the env override must be reported as blocked, not applied."""

    @pytest.mark.parametrize('profile',
                             ['public-hardened', 'private-overlay',
                              'trusted-lan'])
    def test_tls_cannot_be_disabled(self, profile):
        eff = compute_effective_config(
            {'TLS_ENABLED': 'false'}, profile)
        tls = next(e for e in eff if e['name'] == 'TLS_ENABLED')
        assert tls['value'] == 'true'
        assert 'blocked' in tls['source']

    def test_disable_ssl_cannot_be_set(self):
        eff = compute_effective_config(
            {'DISABLE_SSL': 'true'}, 'trusted-lan')
        ds = next(e for e in eff if e['name'] == 'DISABLE_SSL')
        assert ds['value'] == 'false'

    def test_nginx_cannot_be_disabled(self):
        eff = compute_effective_config(
            {'NGINX_ENABLED': 'false'}, 'public-hardened')
        ngx = next(e for e in eff if e['name'] == 'NGINX_ENABLED')
        assert ngx['value'] == 'true'

    def test_mfa_locked_in_mfa_profiles(self):
        for profile in ('public-hardened', 'private-overlay'):
            eff = compute_effective_config(
                {'MFA_REQUIRED': 'false'}, profile)
            mfa = next(e for e in eff if e['name'] == 'MFA_REQUIRED')
            assert mfa['value'] == 'true', profile

    def test_mfa_not_locked_in_trusted_lan(self):
        """trusted-lan does not mandate MFA — an explicit false must
        survive (the lock set is per-profile)."""
        eff = compute_effective_config(
            {'MFA_REQUIRED': 'false'}, 'trusted-lan')
        mfa = next(e for e in eff if e['name'] == 'MFA_REQUIRED')
        assert mfa['value'] == 'false'

    def test_host_overrides_blocked(self):
        """USER_UI_HOST=0.0.0.0 must not survive a hardened profile —
        a public backend bind bypasses the nginx auth gateway."""
        eff = compute_effective_config(
            {'USER_UI_HOST': '0.0.0.0'}, 'public-hardened')
        host = next(e for e in eff if e['name'] == 'USER_UI_HOST')
        assert host['value'] == '127.0.0.1'

    def test_unlocked_var_user_wins(self):
        """Non-locked vars still honour the operator's env."""
        eff = compute_effective_config(
            {'SESSION_IDLE_TIMEOUT': '42'}, 'public-hardened')
        sit = next(e for e in eff if e['name'] == 'SESSION_IDLE_TIMEOUT')
        assert sit['value'] == '42'
        assert sit['source'] == 'env'


class TestPortVars:
    @pytest.mark.parametrize('val', ['0', '-1', '65536', 'abc'])
    def test_out_of_range_or_invalid(self, val):
        f = _find({'VNC_PORT': val})
        assert any('VNC_PORT' in x['message'] for x in _critical(f)), val

    @pytest.mark.parametrize('val', ['1', '5900', '65535'])
    def test_valid_boundary_ports(self, val):
        f = _find({'VNC_PORT': val})
        assert not any('VNC_PORT' in x['message'] for x in _critical(f))


class TestVncPassword:
    def test_empty_no_generated_critical(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda n: '', raising=False)
        f = _find({'VNC_PASSWORD': ''})
        assert any('VNC_PASSWORD' in x['message'] for x in _critical(f))

    def test_generated_credential_counts(self, monkeypatch):
        """A persisted generated password must not be flagged empty."""
        monkeypatch.setattr(
            'vnc_remote_secure.core.config._load_generated_credential',
            lambda n: 'gen-secret-42', raising=False)
        f = _find({'VNC_PASSWORD': ''})
        assert not any(
            'VNC_PASSWORD is empty' in x['message'] for x in _critical(f))

    @pytest.mark.parametrize('pw', ['changeme', 'admin123', 'password'])
    def test_weak_password_critical(self, pw):
        f = _find({'VNC_PASSWORD': pw})
        assert any('weak' in x['message'].lower() for x in _critical(f))


class TestRedaction:
    def test_credential_values_redacted(self):
        """show-effective must never print real credential values."""
        eff = compute_effective_config(
            {'VNC_PASSWORD': 'Sup3rSecret'}, 'development')
        vnc = next(e for e in eff if e['name'] == 'VNC_PASSWORD')
        assert 'Sup3rSecret' not in str(vnc)


class TestUnknownEnvKeys:
    """A typo'd .env key (VNC_PASWORD) silently does nothing while
    the operator believes a control is set — validate must flag it."""

    def _with_env(self, tmp_path, monkeypatch, content):
        env = tmp_path / '.env'
        env.write_text(content)
        monkeypatch.setattr(
            'vnc_remote_secure.core.paths.find_project_root',
            lambda: str(tmp_path))
        # find_project_root may be bound into the inspector module too
        import vnc_remote_secure.core.paths as paths_mod
        from vnc_remote_secure.core import config_inspector as ci
        monkeypatch.setattr(
            paths_mod, 'find_project_root', lambda: str(tmp_path))
        return ci

    def test_unknown_key_warns(self, tmp_path, monkeypatch):
        ci = self._with_env(
            tmp_path, monkeypatch, 'VNC_PASWORD=hunter2\n')
        findings = ci.validate_config(env_snapshot={})
        assert any('VNC_PASWORD' in f['message'] and
                   f['severity'] == 'warning'
                   for f in findings)

    def test_known_key_no_warn(self, tmp_path, monkeypatch):
        ci = self._with_env(
            tmp_path, monkeypatch, 'VNC_PORT=5900\n')
        findings = ci.validate_config(env_snapshot={})
        assert not any('Unknown config key' in f['message']
                       for f in findings)

    def test_missing_schema_no_crash(self, tmp_path, monkeypatch):
        """Schema unloadable -> no findings, no crash (fail open for
        a lint-level check)."""
        ci = self._with_env(
            tmp_path, monkeypatch, 'WHATEVER=1\n')
        monkeypatch.setattr(ci, '_schema_known_vars', set)
        findings = ci.validate_config(env_snapshot={})
        assert not any('Unknown config key' in f['message']
                       for f in findings)



class TestSchemaCoverage:
    """Every schema-declared key must survive the effective-config
    filter — a parallel prefix list once dropped entire var families
    (AUDIT_*, TERMINAL_*, RFB_*)."""

    def test_all_schema_keys_appear_when_set(self):
        from vnc_remote_secure.core.config_inspector import _schema_known_vars
        schema_keys = _schema_known_vars()
        assert schema_keys, 'schema not found'
        env = {k: 'x' for k in schema_keys}
        eff = {e['name'] for e in compute_effective_config(
            env_snapshot=env, profile_name='development')}
        missing = schema_keys - eff
        assert not missing, f'schema keys filtered out: {missing}'
