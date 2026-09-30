"""Operator use-case guards: last-admin protection, admin:* grant
requirement, session revocation on sensitive changes, tombstone
restore. Stores are faked at the ``stores`` seam."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.engine.application import operators  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_CONFLICT,
    ERR_LAST_ADMIN,
    ERR_NOT_FOUND,
    ERR_PERMISSION,
    UseCaseError,
)

ADMIN = {'admin:*', 'admin_users'}
NONADMIN = {'admin_users'}


def _make_env(monkeypatch, ops, *, env_admin=True):
    """In-memory operator store + spy stores.

    ``env_admin`` controls whether the env bootstrap admin exists
    (LANDING_PASSWORD set) — it counts toward viable_admin_count.
    """
    from vnc_remote_secure.engine.infrastructure import stores

    state = {
        'ops': ops,
        'tombstones': {},
        'audits': [],
        'revoked': [],
        'jobs': [],
    }

    class _BE:
        def set_ttl(self, ns, key, value, ttl):
            state['revoked'].append((ns, key))

    monkeypatch.setattr(stores, 'operator_load_store',
                        lambda: state['ops'])
    monkeypatch.setattr(stores, 'operator_roles',
                        lambda: ('viewer', 'admin'))
    monkeypatch.setattr(
        stores, 'env',
        lambda name: 'x' if name == 'LANDING_PASSWORD' and env_admin
        else None)
    monkeypatch.setattr(stores, 'shared_backend', lambda: _BE())
    monkeypatch.setattr(
        stores, 'audit',
        lambda ev, user, detail='':
        state['audits'].append((ev, user, detail)))
    monkeypatch.setattr(
        stores, 'operator_add',
        lambda u, p, role: state['ops'].__setitem__(
            u, {'role': role, 'disabled': False}))
    monkeypatch.setattr(
        stores, 'operator_set_role',
        lambda u, role: state['ops'][u].__setitem__('role', role)
        or True)
    monkeypatch.setattr(
        stores, 'operator_set_disabled',
        lambda u, d: state['ops'][u].__setitem__('disabled', d)
        or True)
    monkeypatch.setattr(
        stores, 'operator_set_password', lambda u, p: True)
    monkeypatch.setattr(
        stores, 'operator_remove',
        lambda u: state['ops'].pop(u, None) is not None)
    monkeypatch.setattr(
        stores, 'tombstone_save',
        lambda u, rec: state['tombstones'].__setitem__(u, dict(rec)))
    monkeypatch.setattr(
        stores, 'tombstones', lambda: list(state['tombstones'].items()))
    monkeypatch.setattr(
        stores, 'tombstone_get',
        lambda u: state['tombstones'].get(u))
    monkeypatch.setattr(
        stores, 'tombstone_remove',
        lambda u: state['tombstones'].pop(u, None))
    monkeypatch.setattr(stores, 'job_start', lambda *a: 'jid-1')
    monkeypatch.setattr(
        stores, 'job_fail',
        lambda j, msg='': state['jobs'].append(('fail', j, msg)))
    monkeypatch.setattr(
        stores, 'job_finish',
        lambda j, msg='': state['jobs'].append(('finish', j, msg)))
    return state


def _admins(env_admin=False):
    return {'root': {'role': 'admin', 'disabled': False},
            'op1': {'role': 'viewer', 'disabled': False}}


# --- create ------------------------------------------------------------------

def test_create_admin_requires_admin_umbrella(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    with pytest.raises(UseCaseError) as exc:
        operators.create_operator(
            'op1', NONADMIN, 'new', 'pw12345678', 'admin', True)
    assert exc.value.code == ERR_PERMISSION
    assert 'new' not in env['ops']
    assert env['audits'][-1][0] == 'api_permission_denied'


def test_create_viewer_ok(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    operators.create_operator(
        'root', ADMIN, 'new', 'pw12345678', 'viewer', True)
    assert env['ops']['new']['role'] == 'viewer'
    assert env['audits'][-1][0] == 'operator_created'


def test_create_unknown_role(monkeypatch):
    _make_env(monkeypatch, _admins())
    with pytest.raises(UseCaseError):
        operators.create_operator(
            'root', ADMIN, 'new', 'pw12345678', 'superuser', True)


# --- update ------------------------------------------------------------------

def test_demote_last_admin_blocked(monkeypatch):
    """Without an env bootstrap admin and a single store admin,
    demoting it must fail with ERR_LAST_ADMIN."""
    _make_env(monkeypatch, _admins(), env_admin=False)
    with pytest.raises(UseCaseError) as exc:
        operators.update_operator(
            'root', ADMIN, 'root', role='viewer')
    assert exc.value.code == ERR_LAST_ADMIN


def test_demote_last_admin_allowed_with_env_admin(monkeypatch):
    """The env bootstrap admin still counts — the demotion leaves an
    administrator (it just can't be the UI account any more)."""
    _make_env(monkeypatch, _admins(), env_admin=True)
    operators.update_operator('root', ADMIN, 'root', role='viewer')
    # 'root' is now a viewer — demotion went through.


def test_grant_admin_requires_admin_umbrella(monkeypatch):
    _make_env(monkeypatch, _admins())
    with pytest.raises(UseCaseError) as exc:
        operators.update_operator(
            'op1', NONADMIN, 'op1', role='admin')
    assert exc.value.code == ERR_PERMISSION


def test_disable_last_admin_blocked(monkeypatch):
    _make_env(monkeypatch, _admins(), env_admin=False)
    with pytest.raises(UseCaseError) as exc:
        operators.update_operator(
            'root', ADMIN, 'root', disabled=True)
    assert exc.value.code == ERR_LAST_ADMIN


def test_role_change_revokes_target_sessions(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    operators.update_operator('root', ADMIN, 'op1', role='admin')
    assert ('op_revoked_users', 'op1') in env['revoked']


def test_password_change_revokes_sessions(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    operators.update_operator(
        'root', ADMIN, 'op1', password='newsecret123')
    assert ('op_revoked_users', 'op1') in env['revoked']


def test_update_unknown_operator(monkeypatch):
    _make_env(monkeypatch, _admins())
    with pytest.raises(UseCaseError) as exc:
        operators.update_operator('root', ADMIN, 'ghost', role='viewer')
    assert exc.value.code == ERR_NOT_FOUND


# --- delete / restore --------------------------------------------------------

def test_delete_last_admin_blocked(monkeypatch):
    _make_env(monkeypatch, _admins(), env_admin=False)
    with pytest.raises(UseCaseError) as exc:
        operators.delete_operator('root', 'root')
    assert exc.value.code == ERR_LAST_ADMIN
    # no job was started — the guard runs before the ledger entry.


def test_delete_tombstones_and_revokes(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    operators.delete_operator('root', 'op1')
    assert 'op1' not in env['ops']
    assert 'op1' in env['tombstones']
    assert ('op_revoked_users', 'op1') in env['revoked']
    assert env['jobs'][-1][0] == 'finish'


def test_restore_recreates_disabled(monkeypatch):
    env = _make_env(monkeypatch, {})
    env['tombstones']['gone'] = {'role': 'admin'}
    rec = operators.restore_operator('root', 'gone')
    assert env['ops']['gone']['disabled'] is True
    assert env['ops']['gone']['role'] == 'admin'
    assert 'gone' not in env['tombstones']
    assert rec['disabled'] is True


def test_restore_conflict_when_exists(monkeypatch):
    env = _make_env(monkeypatch, _admins())
    env['tombstones']['op1'] = {'role': 'viewer'}
    with pytest.raises(UseCaseError) as exc:
        operators.restore_operator('root', 'op1')
    assert exc.value.code == ERR_CONFLICT
