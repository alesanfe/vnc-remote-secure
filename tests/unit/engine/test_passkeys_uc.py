"""Passkey use-case guards: self-service registration, ref→credential
resolution without cross-user oracle, last-factor removal refusal."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.engine.application import passkeys  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_INVALID,
    ERR_LAST_ADMIN,
    ERR_NOT_FOUND,
    ERR_PERMISSION,
    ERR_STEP_UP,
    UseCaseError,
)


@pytest.fixture
def env(monkeypatch):
    """Fake stores + a known credential for 'alice'."""
    from vnc_remote_secure.engine.infrastructure import stores
    state = {
        'creds': {
            'alice': [{'credential_id': 'cred-alice-1',
                       'name': 'key1', 'sign_count': 3}],
            'bob': [{'credential_id': 'cred-bob-1', 'name': 'b'}],
        },
        'audits': [],
        'deleted': [],
        'ops': {'alice': {'password_hash': 'x'}},
    }
    monkeypatch.setattr(
        stores, 'credential_list',
        lambda u: state['creds'].get(u, []))
    monkeypatch.setattr(stores, 'credential_rename',
                        lambda cid, name: True)
    monkeypatch.setattr(
        stores, 'credential_delete',
        lambda cid, u: state['deleted'].append(cid) or True)
    monkeypatch.setattr(stores, 'webauthn_gate_error', lambda: '')
    monkeypatch.setattr(stores, 'step_up_error', lambda a, act: '')
    monkeypatch.setattr(
        stores, 'audit',
        lambda ev, user, detail='', result='':
        state['audits'].append((ev, user)))
    monkeypatch.setattr(stores, 'operator_load_store',
                        lambda: state['ops'])
    monkeypatch.setattr(stores, 'env', lambda n: '')
    monkeypatch.setattr(stores, 'mfa_required', lambda: False)
    monkeypatch.setattr(stores, 'mfa_available', lambda: True)
    monkeypatch.setattr(stores, 'webauthn_begin',
                        lambda u, rp, name: {'challenge': 'x'})
    monkeypatch.setattr(stores, 'webauthn_complete',
                        lambda u, c, rp, origin, name='': (True, 'ok'))
    return state


ALICE = {'operator'}
ADMIN = {'admin_users'}


def test_list_never_leaks_credential_id(env):
    out = passkeys.list_passkeys('alice')
    assert out[0]['ref'] != 'cred-alice-1'
    assert len(out[0]['ref']) == 16
    assert 'credential_id' not in out[0]


def test_ref_resolution_is_scoped_to_owner(env):
    """bob's ref under alice must not resolve — no oracle."""
    bob_ref = passkeys.credential_ref('cred-bob-1')
    with pytest.raises(UseCaseError) as exc:
        passkeys.rename_passkey('alice', ALICE, 'alice', bob_ref, 'x')
    assert exc.value.code == ERR_NOT_FOUND


def test_ref_rejects_non_hex(env):
    with pytest.raises(UseCaseError) as exc:
        passkeys.rename_passkey(
            'alice', ALICE, 'alice', 'zz' + '0' * 14, 'x')
    assert exc.value.code == ERR_NOT_FOUND


def test_registration_self_service_only(env):
    with pytest.raises(UseCaseError) as exc:
        passkeys.begin_registration('alice', 'bob')
    assert exc.value.code == ERR_PERMISSION


def test_registration_requires_recent_auth(env, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores
    monkeypatch.setattr(stores, 'step_up_error',
                        lambda a, act: 'stale session')
    with pytest.raises(UseCaseError) as exc:
        passkeys.begin_registration('alice', 'alice')
    assert exc.value.code == ERR_STEP_UP
    assert env['audits'][-1][0] == 'api_permission_denied'


def test_feature_off_gate(env, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores
    monkeypatch.setattr(stores, 'webauthn_gate_error',
                        lambda: 'webauthn disabled')
    with pytest.raises(UseCaseError) as exc:
        passkeys.begin_registration('alice', 'alice')
    assert exc.value.code == ERR_INVALID


def test_manage_requires_owner_or_admin(env):
    with pytest.raises(UseCaseError) as exc:
        passkeys.delete_passkey('mallory', ALICE, 'alice', 'x' * 16)
    assert exc.value.code == ERR_PERMISSION
    # admin_users can manage someone else's passkey
    ref = passkeys.credential_ref('cred-alice-1')
    passkeys.rename_passkey('admin', ADMIN, 'alice', ref, 'renamed')


def test_delete_last_passkey_refused_without_fallback(env, monkeypatch):
    """No password AND MFA required-but-unavailable → lockout risk."""
    from vnc_remote_secure.engine.infrastructure import stores
    monkeypatch.setitem(env['ops'], 'alice', {})  # no password_hash
    monkeypatch.setattr(stores, 'mfa_required', lambda: True)
    monkeypatch.setattr(stores, 'mfa_available', lambda: False)
    ref = passkeys.credential_ref('cred-alice-1')
    with pytest.raises(UseCaseError) as exc:
        passkeys.delete_passkey('alice', ALICE, 'alice', ref)
    assert exc.value.code == ERR_LAST_ADMIN
    assert env['deleted'] == []


def test_delete_last_passkey_ok_with_password(env):
    ref = passkeys.credential_ref('cred-alice-1')
    passkeys.delete_passkey('alice', ALICE, 'alice', ref)
    assert env['deleted'] == ['cred-alice-1']
    assert env['audits'][-1][0] == 'passkey_revoked'
