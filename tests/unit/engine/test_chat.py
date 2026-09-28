"""Unit tests for engine.application.chat — the session-scoped
guest ↔ operator channel.

The session store and the shared-state backend are faked at the
``stores`` seam / ``shared_state.get_backend`` — the tests pin down
channel lifetime (dead session = dead channel), bounds and auditing.
"""
import time

import pytest

from vnc_remote_secure.engine.application import chat


class _FakeBackend:
    """Minimal dict-backed shared-state backend."""

    def __init__(self):
        self.data = {}
        self.ttls = {}

    def get(self, ns, key):
        return self.data.get((ns, key))

    def set_ttl(self, ns, key, value, ttl):
        self.data[(ns, key)] = value
        self.ttls[(ns, key)] = ttl


class _FakeStore:
    def __init__(self, sessions):
        self._sessions = sessions

    def list_all(self):
        return self._sessions


def _session(token_id='tid-1', **kw):
    s = {'token_id': token_id, 'revoked': False,
         'expires_at': time.time() + 3600}
    s.update(kw)
    return s


@pytest.fixture
def env(monkeypatch):
    backend = _FakeBackend()
    audits = []
    import vnc_remote_secure.engine.infrastructure.stores as s
    import vnc_remote_secure.security.shared_state as ss
    monkeypatch.setattr(ss, 'get_backend', lambda: backend)
    monkeypatch.setattr(
        s, 'audit',
        lambda ev, user, detail='': audits.append((ev, user, detail)))
    state = {'sessions': [_session()]}
    monkeypatch.setattr(s, 'session_store',
                        lambda: _FakeStore(state['sessions']))
    return {'backend': backend, 'audits': audits, 'state': state}


# --- Reads ----------------------------------------------------------------------

def test_list_unknown_session_returns_empty(env):
    assert chat.list_messages('no-such') == []


def test_list_messages(env):
    chat.post_message('tid-1', 'op', 'hola')
    msgs = chat.list_messages('tid-1')
    assert len(msgs) == 1 and msgs[0]['text'] == 'hola'


# --- Writes -----------------------------------------------------------------------

def test_post_unknown_session(env):
    with pytest.raises(ValueError):
        chat.post_message('no-such', 'op', 'x')


def test_post_rejects_dead_session(env):
    env['state']['sessions'] = [_session(revoked=True)]
    with pytest.raises(ValueError):
        chat.post_message('tid-1', 'op', 'x')
    env['state']['sessions'] = [
        _session(expires_at=time.time() - 5)]
    with pytest.raises(ValueError):
        chat.post_message('tid-1', 'op', 'x')


def test_post_rejects_empty(env):
    with pytest.raises(ValueError):
        chat.post_message('tid-1', 'op', '   ')


def test_post_truncates_and_audits(env):
    msg = chat.post_message('tid-1', 'op', 'x' * 900)
    assert len(msg['text']) == 500
    ev, user, detail = env['audits'][-1]
    assert ev == 'session_chat_message' and user == 'op'
    assert 'token_id=tid-1' in detail


def test_history_capped(env):
    for i in range(205):
        chat.post_message('tid-1', 'g', f'm{i}')
    msgs = chat.list_messages('tid-1')
    assert len(msgs) == 200
    assert msgs[0]['text'] == 'm5' and msgs[-1]['text'] == 'm204'


def test_ttl_tracks_session_expiry(env):
    expires = time.time() + 120
    env['state']['sessions'] = [_session(expires_at=expires)]
    chat.post_message('tid-1', 'op', 'x')
    ttl = env['backend'].ttls[('session_chat', 'tid-1')]
    # expires_at - now + _TTL_GRACE, floored at 60.
    assert ttl > 120 + 3000
