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
            return {'desktop:keyboard': self._c,
                    'desktop:pointer': self._c,
                    'desktop:clipboard_write': self._cl}.get(
                        perm, False)

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

    def _handler(self, stub_handler, headers=None):
        return stub_handler(H, headers=headers, path='/websockify')

    def test_bad_origin_403_and_rate_limited(self, monkeypatch, stub_handler):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        h = self._handler(stub_handler,
                          headers={'Origin': 'https://evil.example'})
        h._proxy_websocket()
        h._ws_error.assert_called_once()
        assert h._ws_error.call_args[0][0] == 403
        h._record_ws_origin_failure.assert_called_once()

    def test_upstream_down_502(self, monkeypatch, stub_handler):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        import socket as _s
        monkeypatch.setattr(
            _s, 'create_connection',
            lambda *a, **k: (_ for _ in ()).throw(OSError('down')))
        h = self._handler(stub_handler,
                          headers={'Origin': 'https://ok.example'})
        h._proxy_websocket()
        assert h._ws_error.call_args[0][0] == 502

    def test_toctou_revoke_returns_early(self, monkeypatch, stub_handler):
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
        h = self._handler(stub_handler, headers={
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


class TestRelayCleanup:
    """conn_id must be unregistered on EVERY relay exit — a stale
    registry entry keeps a dead socket's close callback alive and
    prevents revocation propagation."""

    def _setup(self, monkeypatch, unreg):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        import socket as _s
        upstream = type('U', (), {'close': lambda self: None,
                                  'sendall': lambda self, b: None})()
        monkeypatch.setattr(_s, 'create_connection',
                            lambda *a, **k: upstream)
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._register_ws',
            lambda *a, **k: 'conn_7')
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._ephemeral_token',
            lambda *a, **k: 'tok', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.websocket_registry.'
            'unregister_connection',
            lambda cid: unreg.append(cid))
        return upstream

    def test_unregister_on_relay_end(self, monkeypatch, stub_handler):
        unreg = []
        self._setup(monkeypatch, unreg)
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.relay_rfb_stream',
            lambda *a: None)
        h = TestProxyWebsocketGate()._handler(stub_handler, headers={
            'Origin': 'https://ok.example',
            'Cookie': 'vnc_session=tok'})
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._authenticate',
            lambda *a, **k: (True, 'tok'), raising=False)
        h._proxy_websocket()
        assert unreg == ['conn_7']

    def test_unregister_on_relay_oserror(self, monkeypatch, stub_handler):
        unreg = []
        self._setup(monkeypatch, unreg)
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.relay_rfb_stream',
            lambda *a: (_ for _ in ()).throw(OSError('reset')))
        h = TestProxyWebsocketGate()._handler(stub_handler, headers={
            'Origin': 'https://ok.example',
            'Cookie': 'vnc_session=tok'})
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._authenticate',
            lambda *a, **k: (True, 'tok'), raising=False)
        h._proxy_websocket()
        assert unreg == ['conn_7']

    def test_unregister_on_header_encode_failure(self, monkeypatch, stub_handler):
        """A header value unencodable in latin-1 must close upstream
        AND unregister — not leak the registration."""
        unreg = []
        self._setup(monkeypatch, unreg)
        h = TestProxyWebsocketGate()._handler(stub_handler, headers={
            'Origin': 'https://ok.example',
            'Cookie': 'vnc_session=tok',
            'X-Bad': '\u20ac',  # euro sign — not latin-1
        })
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._authenticate',
            lambda *a, **k: (True, 'tok'), raising=False)
        h._proxy_websocket()
        assert unreg == ['conn_7']


class TestRfbFilterFailClosed:
    """A restricted session whose filter cannot be built must NOT
    degrade to unfiltered proxying (fail-closed)."""

    def test_store_failure_fails_closed(self, monkeypatch):
        """_build_rfb_filter raises _RfbFilterError so the caller
        denies the upgrade instead of proxying byte-transparent."""
        import pytest

        from vnc_remote_secure.services.novnc import _RfbFilterError

        class _BrokenStore:
            def _load_if_changed(self):
                pass

            def get(self, tok):
                raise RuntimeError("store corrupted")

        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.get_session_store',
            lambda: _BrokenStore())
        with pytest.raises(_RfbFilterError):
            H._build_rfb_filter('tok')


class TestProxyWebsocketFilterDenial:
    """The websockify path must 403 when a restricted session's RFB
    filter cannot be constructed - never proxy byte-transparent."""

    def test_filter_error_denies_upgrade(self, monkeypatch, stub_handler):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        import socket as _s
        closed = []
        upstream = type('U', (), {
            'close': lambda self: closed.append(1),
            'sendall': lambda self, b: None})()
        monkeypatch.setattr(_s, 'create_connection',
                            lambda *a, **k: upstream)
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.'
            '_AuthedSimpleHTTPRequestHandler._build_rfb_filter',
            staticmethod(lambda tok: (_ for _ in ()).throw(
                __import__(
                    'vnc_remote_secure.services.novnc',
                    fromlist=['_RfbFilterError'])._RfbFilterError('x'))))
        relayed = []
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc.relay_rfb_stream',
            lambda *a: relayed.append(1))
        h = stub_handler(H, headers={
            'Origin': 'https://ok.example',
            'Cookie': 'vnc_ephemeral=tok'})
        h._proxy_websocket()
        assert h.send_response.call_args[0][0] == 403
        assert closed == [1]
        assert relayed == []
