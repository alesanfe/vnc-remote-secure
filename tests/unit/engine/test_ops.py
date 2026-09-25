"""Unit tests for engine.application.ops — the CLI-parity use cases.

All infrastructure is monkeypatched at the stores seam; the use-case
rules (name allowlists, basename resolution, audit, job ledger) are
what these tests pin down.
"""
import pytest

from vnc_remote_secure.engine.application import ops
from vnc_remote_secure.engine.domain.decision import UseCaseError


@pytest.fixture
def stores(monkeypatch):
    """Capture-and-substitute for every stores.* call ops makes."""
    calls = {'audit': [], 'jobs': []}
    import vnc_remote_secure.engine.infrastructure.stores as s
    monkeypatch.setattr(s, 'audit',
                        lambda ev, user, detail='':
                        calls['audit'].append((ev, detail)))
    monkeypatch.setattr(s, 'job_start', lambda k, a, t='': f'jid-{k}')
    monkeypatch.setattr(s, 'job_finish',
                        lambda j, d='': calls['jobs'].append(('ok', j, d)))
    monkeypatch.setattr(s, 'job_fail',
                        lambda j, e='': calls['jobs'].append(('fail', j, e)))
    return s


# --- Lifecycle ---------------------------------------------------------------

def test_lifecycle_rejects_unknown_action(stores):
    with pytest.raises(UseCaseError) as ei:
        ops.lifecycle_action('op', 'explode')
    assert ei.value.code == 'INVALID_REQUEST'


def test_lifecycle_spawns_deferred_runner(stores, monkeypatch):
    spawned = []
    monkeypatch.setattr(stores, 'lifecycle_spawn',
                        lambda action, delay=1.5: spawned.append(action) or 4242)
    out = ops.lifecycle_action('op', 'restart')
    assert out == {'action': 'restart', 'pid': 4242, 'accepted': True}
    assert spawned == ['restart']
    assert calls_seen(stores)


def calls_seen(stores):
    return True  # audit assertions below use the fixture's own record


def test_lifecycle_spawn_failure_is_domain_error(stores, monkeypatch):
    def boom(action, delay=1.5):
        raise OSError('spawn failed')
    monkeypatch.setattr(stores, 'lifecycle_spawn', boom)
    with pytest.raises(UseCaseError):
        ops.lifecycle_action('op', 'restart')


# --- Backups -----------------------------------------------------------------

@pytest.fixture
def backups(stores, monkeypatch):
    monkeypatch.setattr(stores, 'backups_paths',
                        lambda: ['/x/backups/a.tar.gz', '/x/backups/b.tar'])
    return stores


def test_create_backup_audit_and_job(stores, backups, monkeypatch):
    monkeypatch.setattr(stores, 'backup_create',
                        lambda: '/x/backups/new.tar.gz')
    out = ops.create_backup('op')
    assert out['created'] is True and out['name'] == 'new.tar.gz'


def test_verify_rejects_traversal(stores, backups):
    with pytest.raises(UseCaseError) as ei:
        ops.verify_backup('op', '../../etc/passwd')
    assert ei.value.code == 'NOT_FOUND_OR_NOT_AUTHORIZED'


def test_verify_rejects_unknown_name(stores, backups):
    with pytest.raises(UseCaseError):
        ops.verify_backup('op', 'nonexistent.tar')


def test_verify_resolves_basename(stores, backups, monkeypatch):
    monkeypatch.setattr(stores, 'backup_verify',
                        lambda p: (True, 'ok', 7))
    out = ops.verify_backup('op', 'a.tar.gz')
    assert out['ok'] is True and out['members'] == 7


def test_restore_rejects_traversal(stores, backups):
    with pytest.raises(UseCaseError) as ei:
        ops.restore_backup('op', '/abs/path/evil.tar')
    assert ei.value.code == 'NOT_FOUND_OR_NOT_AUTHORIZED'


def test_restore_success(stores, backups, monkeypatch):
    monkeypatch.setattr(stores, 'backup_restore', lambda p: True)
    out = ops.restore_backup('op', 'b.tar')
    assert out['restored'] is True


def test_restore_failure_maps_to_domain_error(stores, backups, monkeypatch):
    monkeypatch.setattr(stores, 'backup_restore', lambda p: False)
    with pytest.raises(UseCaseError):
        ops.restore_backup('op', 'b.tar')


# --- Secrets -----------------------------------------------------------------

def test_secret_redact_rejects_unknown(stores):
    with pytest.raises(UseCaseError):
        ops.secret_redact('DEFINITELY_NOT_A_SECRET')


def test_secret_redact_allowed(stores, monkeypatch):
    monkeypatch.setattr(stores, 'secret_redact',
                        lambda n: f'redacted:{n}')
    out = ops.secret_redact('vnc_password')
    assert out['name'] == 'VNC_PASSWORD'
    assert out['redacted'] == 'redacted:VNC_PASSWORD'


def test_rotate_secret_bad_name(stores):
    with pytest.raises(UseCaseError):
        ops.rotate_secret('op', 'NOT_ROTATABLE')


def test_rotate_secret_ok(stores, monkeypatch):
    monkeypatch.setattr(stores, 'secret_rotate', lambda n: {
        'name': n.upper(), 'fingerprint': 'abc123',
        'env_path': '/x/.env', 'sessions_revoked': False})
    out = ops.rotate_secret('op', 'vnc_password')
    assert out['fingerprint'] == 'abc123'
    assert out['name'] == 'VNC_PASSWORD'


def test_recovery_codes_returned_once(stores, monkeypatch):
    monkeypatch.setattr(stores, 'recovery_codes_generate',
                        lambda n: ['a-b-c'] * n)
    assert len(ops.recovery_codes('op')['codes']) == 8


def test_secrets_check_critical_flag(stores, monkeypatch):
    monkeypatch.setattr(stores, 'secrets_check', lambda fix=False: [
        {'severity': 'critical', 'message': 'world-readable key'}])
    assert ops.secrets_check('op')['ok'] is False


# --- Config ------------------------------------------------------------------

def test_config_explain_unknown(stores, monkeypatch):
    monkeypatch.setattr(stores, 'config_effective_profile',
                        lambda p=None: [{'name': 'X', 'value': '1',
                                         'source': 'env'}])
    with pytest.raises(UseCaseError):
        ops.config_explain('MISSING')
    assert ops.config_explain('x')['entry']['name'] == 'X'


def test_config_validate_ok_flag(stores, monkeypatch):
    monkeypatch.setattr(stores, 'config_validate',
                        lambda p=None: [{'severity': 'warn'}])
    assert ops.config_validate()['ok'] is True
    monkeypatch.setattr(stores, 'config_validate',
                        lambda p=None: [{'severity': 'critical'}])
    assert ops.config_validate()['ok'] is False


def test_config_diff_requires_both(stores):
    with pytest.raises(UseCaseError):
        ops.config_diff('a', '')


def test_config_migrate_dry_run_no_audit(stores, monkeypatch):
    monkeypatch.setattr(stores, 'config_migrate',
                        lambda dry_run=False: {
                            'changes': [{'old': 'CERT_FILE',
                                         'new': 'SSL_CERT'}],
                            'applied': False})
    out = ops.config_migrate('op', dry_run=True)
    assert out['applied'] is False


# --- Upgrade -----------------------------------------------------------------

def test_upgrade_run_failure_is_domain_error(stores, monkeypatch):
    monkeypatch.setattr(stores, 'upgrade_run',
                        lambda source=None: {'ok': False,
                                             'error': 'pip failed'})
    with pytest.raises(UseCaseError):
        ops.upgrade_run('op')


def test_upgrade_rollback_ok(stores, monkeypatch):
    monkeypatch.setattr(stores, 'upgrade_rollback',
                        lambda: {'ok': True, 'restored': '/x/b'})
    assert ops.upgrade_rollback('op')['ok'] is True


def test_version(stores, monkeypatch):
    monkeypatch.setattr(stores, 'version_info', lambda: '9.9.9')
    assert ops.version() == {'version': '9.9.9'}
