"""recording.delete bound step-up — the catalog declares
'stepup-bound' so the use case must CONSUME a single-use grant tied
to the operation AND the concrete recording id, not merely pass a
recent-auth window."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.engine.application import recordings  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_STEP_UP,
    UseCaseError,
)


@pytest.fixture
def fakes(monkeypatch):
    """Stub the stores seam — no real backend, no real files."""
    from vnc_remote_secure.engine.infrastructure import stores
    calls = {'consume': [], 'delete': [], 'audit': []}
    monkeypatch.setattr(
        stores, 'step_up_consume',
        lambda user, op, resource, sid: calls['consume'].append(
            (user, op, resource, sid)) or True)
    monkeypatch.setattr(
        stores, 'recording_delete',
        lambda rec_id: calls['delete'].append(rec_id) or True)
    monkeypatch.setattr(
        stores, 'audit',
        lambda ev, user, detail='': calls['audit'].append((ev, user)))
    return calls


def _api_ctx(sid='sid-1'):
    return {'transport': 'api', 'username': 'alice', 'sid': sid}


def test_delete_via_api_consumes_bound_grant(fakes):
    recordings.delete('rec-9', 'alice', _api_ctx())
    assert fakes['consume'] == [
        ('alice', 'recording.delete', 'rec-9', 'sid-1')]
    assert fakes['delete'] == ['rec-9']
    assert fakes['audit'] == [('recording_delete', 'alice')]


def test_delete_via_cli_skips_grant(fakes):
    """No auth_ctx / cli transport: the local shell is the auth
    boundary — no web grant to consume."""
    recordings.delete('rec-1', 'admin')
    assert fakes['consume'] == []
    assert fakes['delete'] == ['rec-1']


def test_delete_without_grant_fails_closed(fakes, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores
    monkeypatch.setattr(stores, 'step_up_consume',
                        lambda *a: False)
    with pytest.raises(UseCaseError) as exc:
        recordings.delete('rec-9', 'alice', _api_ctx())
    assert exc.value.code == ERR_STEP_UP
    # And the file is never touched when the grant fails.
    assert fakes['delete'] == []


def test_delete_grant_is_single_use(fakes, monkeypatch):
    """A grant consumed once cannot authorize a second delete — the
    backend nonce marker makes the second consume return False."""
    consumed = []
    from vnc_remote_secure.engine.infrastructure import stores

    def _consume(user, op, resource, sid):
        key = (user, op, resource, sid)
        if key in consumed:
            return False
        consumed.append(key)
        return True

    monkeypatch.setattr(stores, 'step_up_consume', _consume)
    recordings.delete('rec-9', 'alice', _api_ctx())
    with pytest.raises(UseCaseError):
        recordings.delete('rec-9', 'alice', _api_ctx())
    assert fakes['delete'] == ['rec-9']


def test_delete_unknown_recording_404(fakes, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores
    monkeypatch.setattr(stores, 'recording_delete', lambda rec_id: False)
    with pytest.raises(FileNotFoundError):
        recordings.delete('ghost', 'alice', _api_ctx())
