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
        assert cookies == {'good': '1', '': 'noval'} or cookies == {'good': '1'}


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
