"""Unit tests for the noVNC WebSocket upgrade helpers."""
import pytest

from vnc_remote_secure.services import novnc


class TestParseCookies:
    def test_parses_multiple(self):
        cookies = novnc._parse_cookies('a=1; vnc_session=abc; x=y')
        assert cookies['a'] == '1'
        assert cookies['vnc_session'] == 'abc'
        assert cookies['x'] == 'y'

    def test_empty_header(self):
        assert novnc._parse_cookies('') == {}
        assert novnc._parse_cookies(None) == {}

    def test_ignores_malformed_parts(self):
        cookies = novnc._parse_cookies('nok; good=1; =noval')
        assert cookies == {'good': '1', '': 'noval'}


class TestEphemeralToken:
    def test_cookie_wins(self):
        tok = novnc._ephemeral_token({'vnc_ephemeral': 'c'}, 'bearer')
        assert tok == 'c'

    def test_bearer_fallback_verifies(self, monkeypatch):
        monkeypatch.setattr(
            'vnc_remote_secure.security.ephemeral_sessions.verify_ephemeral_token',
            lambda t: {'session_token': 'inner'} if t == 'good' else None)
        assert novnc._ephemeral_token({}, 'good') == 'inner'
        assert novnc._ephemeral_token({}, 'bad') == ''

    def test_no_credentials(self):
        assert novnc._ephemeral_token({}, '') == ''


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
        def __init__(self, control, clip, clip_r=None):
            self._c, self._cl = control, clip
            self._cr = clip if clip_r is None else clip_r

        def has_permission(self, perm, resource):
            return {'desktop:keyboard': self._c,
                    'desktop:pointer': self._c,
                    'desktop:clipboard_write': self._cl,
                    'desktop:clipboard_read': self._cr}.get(
                        perm, False)

    def test_no_token_no_filter(self):
        assert novnc._build_rfb_filter('') is None

    def test_full_perms_no_filter(self, monkeypatch):
        self._store(monkeypatch, self._Sess(control=True, clip=True))
        assert novnc._build_rfb_filter('tok') is None

    def test_view_only_gets_filter(self, monkeypatch):
        self._store(monkeypatch, self._Sess(control=False, clip=False))
        f = novnc._build_rfb_filter('tok')
        assert f is not None

    def test_write_only_clipboard_gets_filter(self, monkeypatch):
        """clipboard_write without clipboard_read still activates the
        filter — the server->client stream must be parsed to drop
        ServerCutText."""
        self._store(monkeypatch, self._Sess(
            control=True, clip=True, clip_r=False))
        f = novnc._build_rfb_filter('tok')
        assert f is not None
        assert f.allow_clipboard_read is False

    def test_unknown_session_no_filter(self, monkeypatch):
        self._store(monkeypatch, None)
        assert novnc._build_rfb_filter('ghost') is None


class TestRfbFilterFailClosed:
    """A restricted session whose filter cannot be built must NOT
    degrade to unfiltered proxying (fail-closed)."""

    def test_store_failure_fails_closed(self, monkeypatch):
        """_build_rfb_filter raises _RfbFilterError so the route
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
            novnc._build_rfb_filter('tok')


class TestWsPayloads:
    """The message-level relay wraps payloads in synthetic frames for
    the RFB filter and unwraps its framed output — _ws_payloads is
    the unwrap side."""

    def test_extracts_binary_payload(self):
        from vnc_remote_secure.services.rfb_filter import _ws_frame
        framed = _ws_frame(b'RFB-data')
        assert novnc._ws_payloads(framed) == [b'RFB-data']

    def test_multiple_frames(self):
        from vnc_remote_secure.services.rfb_filter import _ws_frame
        framed = _ws_frame(b'one') + _ws_frame(b'two')
        assert novnc._ws_payloads(framed) == [b'one', b'two']

    def test_unmasked_server_frame(self):
        from vnc_remote_secure.services.rfb_filter import _ws_server_frame
        framed = _ws_server_frame(b'srv')
        assert novnc._ws_payloads(framed) == [b'srv']


class TestWebsockifyUpgradeGate:
    """The /websockify route's pre-accept rejection paths — origin
    gate, auth gate, upstream down, TOCTOU revoke — exercised over a
    real uvicorn instance with stubbed boundaries."""

    @pytest.fixture
    def ws_url(self, monkeypatch, asgi_server):
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.get_allowed_origins',
            lambda: ['https://ok.example'], raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc._check_novnc_auth',
            lambda headers, client_ip=None: (True, ''))
        port = asgi_server(novnc.make_app('.'))
        return f'ws://127.0.0.1:{port}/websockify'

    def _connect(self, url, headers):
        import asyncio

        import websockets

        async def _go():
            try:
                async with websockets.connect(
                        url, additional_headers=headers,
                        open_timeout=5) as ws:
                    await ws.recv()
                    return 'connected'
            except websockets.exceptions.InvalidStatus as e:
                return e.response.status_code
            except websockets.exceptions.ConnectionClosed:
                return 'closed'

        return asyncio.run(_go())

    def test_bad_origin_403(self, ws_url):
        status = self._connect(
            ws_url, {'Origin': 'https://evil.example'})
        assert status == 403

    def test_upstream_down_502(self, monkeypatch, ws_url):
        # NOVNC_WS_PORT points at a port with no bridge listening.
        monkeypatch.setenv('NOVNC_WS_PORT', '1')
        status = self._connect(
            ws_url, {'Origin': 'https://ok.example'})
        assert status == 502

    def test_filter_error_denies_403(self, monkeypatch, ws_url):
        """A restricted session whose filter cannot be built gets a
        403 denial — never a byte-transparent proxy."""
        from vnc_remote_secure.services.novnc import _RfbFilterError
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc._build_rfb_filter',
            lambda tok: (_ for _ in ()).throw(_RfbFilterError('x')))
        status = self._connect(
            ws_url, {'Origin': 'https://ok.example',
                     'Cookie': 'vnc_ephemeral=tok'})
        assert status == 403

    def test_auth_failure_401(self, monkeypatch, tmp_path, asgi_server):
        monkeypatch.setattr(
            'vnc_remote_secure.services.novnc._check_novnc_auth',
            lambda headers, client_ip=None: (False, 'no creds'))
        port = asgi_server(novnc.make_app(str(tmp_path)))
        status = self._connect(
            f'ws://127.0.0.1:{port}/websockify',
            {'Origin': 'https://ok.example'})
        assert status == 401
