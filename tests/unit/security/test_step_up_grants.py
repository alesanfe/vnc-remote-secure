"""Unit tests for operation-bound step-up grants and test isolation."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.core import test_isolation  # noqa: E402
from vnc_remote_secure.security import step_up_auth  # noqa: E402


def test_grant_and_consume():
    assert step_up_auth.grant_step_up('op', 'backup.restore', 'b.tar',
                                      sid='s1')
    assert step_up_auth.pending_step_up('op', 'backup.restore', 'b.tar')
    assert step_up_auth.consume_step_up('op', 'backup.restore', 'b.tar',
                                        sid='s1')


def test_consume_is_single_use():
    step_up_auth.grant_step_up('op', 'backup.restore', 'b.tar')
    assert step_up_auth.consume_step_up('op', 'backup.restore', 'b.tar')
    assert not step_up_auth.consume_step_up('op', 'backup.restore', 'b.tar')


def test_consume_rejects_wrong_resource():
    """A grant for backup A must not restore backup B."""
    step_up_auth.grant_step_up('op', 'backup.restore', 'a.tar')
    assert not step_up_auth.consume_step_up('op', 'backup.restore', 'b.tar')
    assert step_up_auth.consume_step_up('op', 'backup.restore', 'a.tar')


def test_consume_rejects_wrong_operation():
    step_up_auth.grant_step_up('op', 'secrets.rotate', 'X')
    assert not step_up_auth.consume_step_up('op', 'backup.create', '')


def test_consume_rejects_foreign_session():
    """A grant minted under sid A must not satisfy sid B."""
    step_up_auth.grant_step_up('op', 'lifecycle.action', 'restart',
                               sid='session-A')
    assert not step_up_auth.consume_step_up(
        'op', 'lifecycle.action', 'restart', sid='session-B')
    assert step_up_auth.consume_step_up(
        'op', 'lifecycle.action', 'restart', sid='session-A')


def test_grants_are_per_user():
    step_up_auth.grant_step_up('alice', 'backup.restore', 'b.tar')
    assert not step_up_auth.consume_step_up(
        'bob', 'backup.restore', 'b.tar')


# --- isolation guard ----------------------------------------------------------

def test_guard_blocks_repo_write_in_test_mode(tmp_path, monkeypatch):
    monkeypatch.setenv('VRS_TEST_MODE', '1')
    repo_env = test_isolation._REPO_ROOT / '.env'
    with pytest.raises(test_isolation.TestIsolationError):
        test_isolation.guard_write(repo_env)


def test_guard_allows_tmp_writes(tmp_path, monkeypatch):
    monkeypatch.setenv('VRS_TEST_MODE', '1')
    test_isolation.guard_write(tmp_path / '.env')  # no raise


def test_guard_allows_override_dir(tmp_path, monkeypatch):
    monkeypatch.setenv('VRS_TEST_MODE', '1')
    monkeypatch.setenv('VRS_DATA_DIR', str(tmp_path / 'data'))
    # A repo path is still refused even with overrides set.
    with pytest.raises(test_isolation.TestIsolationError):
        test_isolation.guard_write(test_isolation._REPO_ROOT / 'backups/x')


def test_guard_noop_outside_test_mode(monkeypatch):
    monkeypatch.delenv('VRS_TEST_MODE', raising=False)
    test_isolation.guard_write(test_isolation._REPO_ROOT / '.env')
    test_isolation.guard_spawn('anything')


def test_guard_spawn_blocks_in_test_mode(monkeypatch):
    monkeypatch.setenv('VRS_TEST_MODE', '1')
    monkeypatch.delenv('VRS_TEST_ALLOW_SPAWN', raising=False)
    with pytest.raises(test_isolation.TestIsolationError):
        test_isolation.guard_spawn('lifecycle runner')
    monkeypatch.setenv('VRS_TEST_ALLOW_SPAWN', '1')
    test_isolation.guard_spawn('lifecycle runner')
