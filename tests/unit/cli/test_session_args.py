"""Regression tests for `session create` argument validation."""
import os
import sys
from argparse import Namespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.cli.commands.session import cmd_session


def _args(**over):
    base = {
        'session_action': 'create', 'expires': '30m', 'role': 'viewer',
        'view_only': False, 'no_terminal': False, 'single_use': False,
        'max_uses': 0, 'allowed_ip': None, 'resource': None, 'json': False,
        'verbose': False,
    }
    base.update(over)
    return Namespace(**base)


def test_max_uses_negative_rejected(capsys):
    rc = cmd_session(_args(max_uses=-1))
    assert rc == 1
    assert '--max-uses' in capsys.readouterr().out


def test_allowed_ip_malformed_rejected(capsys):
    rc = cmd_session(_args(allowed_ip='not-an-ip'))
    assert rc == 1
    assert '--allowed-ip' in capsys.readouterr().out


def _patched_store():
    """Patch the store at its source module (cmd_session imports it
    lazily inside the function)."""
    return patch(
        'vnc_remote_secure.security.ephemeral_sessions.get_session_store')


def test_allowed_ip_valid_accepted(capsys):
    with _patched_store() as gs:
        store = gs.return_value
        store.create.return_value = (object(), 'tok')
        rc = cmd_session(_args(allowed_ip='10.0.0.5'))
        assert rc == 0
        store.create.assert_called_once()
        assert store.create.call_args.kwargs['allowed_ip'] == '10.0.0.5'


def test_allowed_ip_ipv6_accepted(capsys):
    with _patched_store() as gs:
        store = gs.return_value
        store.create.return_value = (object(), 'tok')
        rc = cmd_session(_args(allowed_ip='::1'))
        assert rc == 0


class TestParseDuration:
    """Duration parsing — BVA on unit suffixes and edge values."""

    @pytest.mark.parametrize(('s', 'expected'), [
        ('30m', 1800), ('2h', 7200), ('1d', 86400), ('3600', 3600),
        ('3600s', 3600), (' 30m ', 1800), ('30M', 1800),
    ])
    def test_valid_durations(self, s, expected):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        assert _parse_duration(s) == expected

    @pytest.mark.parametrize('s', ['0', '-5m', '0m', 'abc', '10x', 'x'])
    def test_invalid_durations_raise(self, s):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        with pytest.raises(SystemExit):
            _parse_duration(s)

    def test_empty_returns_default(self):
        from vnc_remote_secure.cli.commands.session import _parse_duration
        from vnc_remote_secure.core.constants import (
            DEFAULT_SESSION_IDLE_TIMEOUT)
        assert _parse_duration('') == DEFAULT_SESSION_IDLE_TIMEOUT
        assert _parse_duration(None) == DEFAULT_SESSION_IDLE_TIMEOUT


class TestSessionActions:
    def test_revoke_not_found(self, capsys):
        monkeypatch_arg = Namespace(
            session_action='revoke', token='nonexistent-tok')
        with patch(
                'vnc_remote_secure.security.ephemeral_sessions.'
                'revoke_session', return_value=False):
            rc = cmd_session(monkeypatch_arg)
        assert rc != 0

    def test_revoke_found(self, capsys):
        args = Namespace(session_action='revoke', token='tok-1')
        with patch(
                'vnc_remote_secure.security.ephemeral_sessions.'
                'revoke_session', return_value=True):
            rc = cmd_session(args)
        assert rc == 0

    def test_list_empty(self, capsys):
        store = type('S', (), {'list_active': lambda self: []})()
        args = Namespace(session_action='list', json=False)
        with patch(
                'vnc_remote_secure.security.ephemeral_sessions.'
                'get_session_store', return_value=store):
            assert cmd_session(args) == 0
        assert 'o active' in capsys.readouterr().out

    def test_list_json_output(self, capsys):
        store = type('S', (), {'list_active': lambda self: [
            {'token_id': 'abc123', 'role': 'viewer',
             'expires_at': 9999999999, 'view_only': True,
             'single_use': True}]})()
        args = Namespace(session_action='list', json=True)
        with patch(
                'vnc_remote_secure.security.ephemeral_sessions.'
                'get_session_store', return_value=store):
            assert cmd_session(args) == 0
        import json
        out = json.loads(capsys.readouterr().out)
        assert out[0]['token_id'] == 'abc123'

    def test_unknown_action(self):
        args = Namespace(session_action='frobnicate')
        rc = cmd_session(args)
        assert rc != 0


class TestShareBaseUrl:
    """Share-link derivation — TLS/nginx/port/domain combinations."""

    def _url(self, monkeypatch, **env):
        for k in ('DUCK_DOMAIN', 'NGINX_ENABLED', 'NGINX_HTTPS_PORT',
                  'LANDING_PORT', 'TLS_ENABLED', 'DISABLE_SSL',
                  'SSL_CERT', 'SSL_KEY'):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        # Cert resolution must not depend on real files.
        monkeypatch.setattr(
            'vnc_remote_secure.security.certificates.create_ssl_context',
            lambda *a: object() if env.get('_TLS', True) else None,
            raising=False)
        from vnc_remote_secure.cli.commands.session import (
            _share_base_url)
        return _share_base_url()

    def test_nginx_tls_default_port_no_suffix(self, monkeypatch):
        monkeypatch.setenv('_TLS', 'x')
        url = self._url(monkeypatch, DUCK_DOMAIN='myhost.duckdns.org',
                        NGINX_ENABLED='true', TLS_ENABLED='true')
        assert url == 'https://myhost.duckdns.org'

    def test_nginx_tls_nondefault_port(self, monkeypatch):
        url = self._url(monkeypatch, DUCK_DOMAIN='myhost.duckdns.org',
                        NGINX_ENABLED='true', TLS_ENABLED='true',
                        NGINX_HTTPS_PORT='8443')
        assert url == 'https://myhost.duckdns.org:8443'

    def test_bare_duck_domain_normalized(self, monkeypatch):
        """'mysub' must become mysub.duckdns.org — a bare token is not
        a resolvable hostname."""
        url = self._url(monkeypatch, DUCK_DOMAIN='mysub',
                        NGINX_ENABLED='true', TLS_ENABLED='true')
        assert url == 'https://mysub.duckdns.org'

    def test_no_nginx_no_tls_http_landing(self, monkeypatch):
        # _url() clears every TLS-related env var; the ssl-context
        # patch makes cert resolution return None.
        monkeypatch.setattr(
            'vnc_remote_secure.security.certificates.create_ssl_context',
            lambda *a: None, raising=False)
        url = self._url(monkeypatch, LANDING_PORT='8000', _TLS='')
        assert url == 'http://127.0.0.1:8000'

    def test_ssl_context_failure_falls_back(self, monkeypatch):
        """create_ssl_context raising must not crash URL derivation —
        fall back to the env flag."""
        monkeypatch.setenv('NGINX_ENABLED', 'true')
        monkeypatch.setenv('TLS_ENABLED', 'true')
        monkeypatch.setenv('DUCK_DOMAIN', 'd.duckdns.org')
        monkeypatch.setattr(
            'vnc_remote_secure.security.certificates.create_ssl_context',
            lambda *a: (_ for _ in ()).throw(RuntimeError('no certs')),
            raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.core.config.get_config',
            lambda: {'tls_enabled': True}, raising=False)
        from vnc_remote_secure.cli.commands.session import (
            _share_base_url)
        assert _share_base_url().startswith('https://')
