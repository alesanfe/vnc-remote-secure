"""Unit tests for the noVNC WebSocket proxy helpers."""
from vnc_remote_secure.services.novnc import (
    _AuthedSimpleHTTPRequestHandler as H,
)


class TestParseCookies:
    def test_parses_multiple(self):
        cookies = H._parse_cookies('a=1; vnc_session=abc; x=y')
        assert cookies['a'] == '1'
        assert cookies['vnc_session'] == 'abc'
        assert cookies['x'] == 'y'

    def test_empty_header(self):
        assert H._parse_cookies('') == {}
        assert H._parse_cookies(None) == {}

    def test_ignores_malformed_parts(self):
        cookies = H._parse_cookies('nok; good=1; =noval')
        assert cookies == {'good': '1', '': 'noval'}


class TestEphemeralToken:
    def test_cookie_wins(self):
        tok = H._ephemeral_token({'vnc_ephemeral': 'c'}, 'bearer')
        assert tok == 'c'

    def test_bearer_fallback_verifies(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.verify_ephemeral_token',
            lambda t: {'session_token': 'inner'} if t == 'good' else None)
        assert H._ephemeral_token({}, 'good') == 'inner'
        assert H._ephemeral_token({}, 'bad') == ''

    def test_no_credentials(self):
        assert H._ephemeral_token({}, '') == ''


class TestBuildRfbFilter:
    def _store(self, monkeypatch, session):
        class _S:
            def _load_if_changed(self):
                pass

            def get(self, tok):
                return session
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
            lambda: _S())

    class _Sess:
        def __init__(self, control, clip):
            self._c, self._cl = control, clip

        def has_permission(self, perm, resource):
            return {'desktop:control': self._c,
                    'desktop:clipboard': self._cl}.get(perm, False)

    def test_no_token_no_filter(self):
        assert H._build_rfb_filter('') is None

    def test_full_perms_no_filter(self, monkeypatch):
        self._store(monkeypatch, self._Sess(control=True, clip=True))
        assert H._build_rfb_filter('tok') is None

    def test_view_only_gets_filter(self, monkeypatch):
        self._store(monkeypatch, self._Sess(control=False, clip=False))
        f = H._build_rfb_filter('tok')
        assert f is not None

    def test_unknown_session_no_filter(self, monkeypatch):
        self._store(monkeypatch, None)
        assert H._build_rfb_filter('ghost') is None


class TestProxyWebsocketGate:
    """_proxy_websocket reject paths — origin gate, upstream down,
    TOCTOU revoke. Exercised via a stub handler, no real socket."""

    def _handler(self, monkeypatch, headers=None):
        from unittest.mock import MagicMock
        h = object.__new__(H)
        h.headers = headers or {}
        h.client_address = ('127.0.0.1', 1)
        h._ws_error = MagicMock()
        h._record_ws_origin_failure = MagicMock()
        h.command = 'GET'
        h.path = '/websockify'
        h.connection = MagicMock()
        h.wfile = MagicMock()
        return h

    def test_bad_origin_403_and_rate_limited(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        h = self._handler(monkeypatch,
                          headers={'Origin': 'https://evil.example'})
        h._proxy_websocket()
        h._ws_error.assert_called_once()
        assert h._ws_error.call_args[0][0] == 403
        h._record_ws_origin_failure.assert_called_once()

    def test_upstream_down_502(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        import socket as _s
        monkeypatch.setattr(
            _s, 'create_connection',
            lambda *a, **k: (_ for _ in ()).throw(OSError('down')))
        h = self._handler(monkeypatch,
                          headers={'Origin': 'https://ok.example'})
        h._proxy_websocket()
        assert h._ws_error.call_args[0][0] == 502

    def test_toctou_revoke_returns_early(self, monkeypatch):
        """_register_ws -> None (session revoked mid-upgrade) must
        return without relaying."""
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        import socket as _s
        upstream = type('U', (), {'close': lambda self: None,
                                  'sendall': lambda self, b: None})()
        monkeypatch.setattr(_s, 'create_connection',
                            lambda *a, **k: upstream)
        h = self._handler(monkeypatch, headers={
            'Origin': 'https://ok.example',
            'Cookie': 'vnc_session=tok',
        })
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.H._register_ws'
            if False else
            'vnc_remote_secure.services.novnc._AuthedSimpleHTTPRequestHandler._register_ws',
            lambda *a, **k: None)
        relayed = []
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.relay_rfb_stream',
            lambda *a: relayed.append(1))
        h._proxy_websocket()
        assert relayed == []
        assert not h._ws_error.called
