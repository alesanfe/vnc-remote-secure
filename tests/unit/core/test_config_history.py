"""Config env-file history: snapshot-on-mutation, listing, rollback."""
import os

import pytest


@pytest.fixture
def env_root(tmp_path, monkeypatch):
    """Project root with a .env — history dir lands under it."""
    env = tmp_path / '.env'
    env.write_text('A=1\nSECRET_KEY=abc\n', encoding='utf-8')
    monkeypatch.setattr(
        'vnc_remote_secure.core.paths.find_project_root',
        lambda: str(tmp_path))
    # _env_targets also asks core.config for the system env path —
    # keep the real one out of the test by giving it a tmp location.
    sys_env = tmp_path / 'system' / 'config.env'
    monkeypatch.setattr(
        'vnc_remote_secure.core.config._system_env_path',
        lambda: str(sys_env))
    return tmp_path, env


def test_snapshot_and_list(env_root):
    from vnc_remote_secure.core import config_history
    _root, env = env_root
    sid = config_history.snapshot(actor='admin', reason='config migrate')
    assert sid
    snaps = config_history.list_history()
    assert len(snaps) == 1
    rec = snaps[0]
    assert rec['id'] == sid
    assert rec['actor'] == 'admin'
    assert rec['reason'] == 'config migrate'
    assert rec['source'] == '.env'
    # The filesystem path must not leak into listing output.
    assert 'source_path' not in rec
    # Snapshot file exists and holds the original bytes.
    blob = env.read_bytes()
    snap_path = env.parent / 'backups' / 'config_history' / f'{sid}.env'
    assert snap_path.read_bytes() == blob


def test_snapshot_no_env(tmp_path, monkeypatch):
    """Fresh install: no .env → no snapshot, no crash."""
    from vnc_remote_secure.core import config_history
    monkeypatch.setattr(
        'vnc_remote_secure.core.paths.find_project_root',
        lambda: str(tmp_path))
    assert config_history.snapshot() is None
    assert config_history.list_history() == []


def test_rollback_restores_content(env_root):
    from vnc_remote_secure.core import config_history
    _root, env = env_root
    sid = config_history.snapshot(actor='admin', reason='test')
    env.write_text('A=2\n', encoding='utf-8')
    result = config_history.rollback(sid, actor='admin')
    assert result['restored'] == sid
    assert env.read_text(encoding='utf-8') == 'A=1\nSECRET_KEY=abc\n'
    # The rollback snapshotted the pre-restore state — undo is possible.
    snaps = config_history.list_history()
    assert len(snaps) == 2


def test_rollback_rejects_bad_id(env_root):
    from vnc_remote_secure.core import config_history
    for bad in ('', '../etc/passwd', 'a/b', 'x' * 200, '123_zzzzzzzz'):
        with pytest.raises(ValueError):
            config_history.rollback(bad)


def test_rollback_unknown_snapshot(env_root):
    from vnc_remote_secure.core import config_history
    with pytest.raises(FileNotFoundError):
        config_history.rollback('1700000000000_deadbeef')


def test_rollback_rejects_untrusted_source(env_root):
    """A forged sidecar pointing at an arbitrary path is refused."""
    import json

    from vnc_remote_secure.core import config_history
    _root, env = env_root
    sid = config_history.snapshot(actor='admin', reason='test')
    sidecar = (env.parent / 'backups' / 'config_history'
               / f'{sid}.json')
    rec = json.loads(sidecar.read_text(encoding='utf-8'))
    rec['source_path'] = str(env.parent / 'PWNED.txt')
    sidecar.write_text(json.dumps(rec), encoding='utf-8')
    with pytest.raises(ValueError):
        config_history.rollback(sid)
    assert not (env.parent / 'PWNED.txt').exists()


def test_migrate_env_snapshots_first(env_root, monkeypatch):
    """The .env mutation path checkpoints before it writes."""
    from vnc_remote_secure.core.config_migration import migrate_env
    _root, env = env_root
    env.write_text('VNC_REMOTE_PROFILE=home-lan\n', encoding='utf-8')
    result = migrate_env(str(env), dry_run=False, actor='tester')
    assert result['applied']
    env.write_text  # silence linters on fixture unpacking
    from vnc_remote_secure.core import config_history
    # _env_targets was patched to tmp — the snapshot names '.env'.
    snaps = config_history.list_history()
    assert len(snaps) == 1
    assert snaps[0]['reason'] == 'config migrate'


def test_label_validation():
    """Labels are bounded printable text — CR/LF/control rejected."""
    from vnc_remote_secure.engine.application.sessions import (
        _validate_label,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    assert _validate_label(None) is None
    assert _validate_label('  soporte Juan  ') == 'soporte Juan'
    with pytest.raises(UseCaseError):
        _validate_label('x' * 65)
    with pytest.raises(UseCaseError):
        _validate_label('evil\nKEY=value')


def test_label_roundtrip(tmp_path, monkeypatch):
    """Label persists through the store's save/load cycle."""
    monkeypatch.setenv('EPHEMERAL_SESSIONS_FILE',
                       str(tmp_path / 'ephemeral.json'))
    monkeypatch.setenv('EPHEMERAL_SIGNING_KEY', 'k' * 32)
    from vnc_remote_secure.security.ephemeral_sessions import (
        get_session_store,
    )
    store = get_session_store()
    session, _signed = store.create(
        expires_in=60, role='viewer', resource='desktop',
        created_by='t', label='demo-uno')
    loaded = store.get(session.token)
    assert loaded is not None
    assert loaded.label == 'demo-uno'
    # Old records without the field deserialize cleanly.
    data = loaded.to_persist_dict()
    data.pop('label')
    assert os.path.exists(tmp_path)
    from vnc_remote_secure.security.ephemeral_sessions import (
        EphemeralSession,
    )
    assert EphemeralSession.from_dict(data).label is None
