"""Unit tests for core.deferred_lifecycle — the detached runner that
lets the REST API restart the service set (including the portal that
served the request)."""
import subprocess
import sys
from unittest import mock

import pytest

from vnc_remote_secure.core import deferred_lifecycle as dl


def test_spawn_rejects_unknown_action():
    with pytest.raises(ValueError):
        dl.spawn_lifecycle('explode')


@pytest.mark.parametrize('action', ['start', 'stop', 'restart'])
def test_spawn_detaches_child(action):
    with mock.patch.object(subprocess, 'Popen') as popen:
        proc = popen.return_value
        proc.pid = 4321
        pid = dl.spawn_lifecycle(action, delay=0.5)
    assert pid == 4321
    args, kwargs = popen.call_args
    assert args[0][0] == sys.executable
    assert args[0][2] == 'vnc_remote_secure.core.deferred_lifecycle'
    assert args[0][3] == action
    # Detached — the child survives when stop/restart kills the parent.
    assert kwargs['stdin'] is not None and kwargs['close_fds'] is True
    if sys.platform == 'win32':
        assert kwargs['creationflags'] & subprocess.CREATE_NEW_PROCESS_GROUP
        assert kwargs['creationflags'] & subprocess.DETACHED_PROCESS
    else:
        assert kwargs['start_new_session'] is True


def test_main_usage_error():
    assert dl.main([]) == 2
    assert dl.main(['nope']) == 2


def test_main_runs_after_delay(monkeypatch):
    slept = []
    ran = []
    monkeypatch.setattr(dl.time, 'sleep', lambda s: slept.append(s))
    monkeypatch.setattr(dl, 'run_action', lambda a: ran.append(a) or 0)
    assert dl.main(['restart', '0.01']) == 0
    assert slept == [0.01]
    assert ran == ['restart']


def test_main_delay_is_bounded(monkeypatch):
    """A huge delay must not park a hidden process for days."""
    slept = []
    monkeypatch.setattr(dl.time, 'sleep', lambda s: slept.append(s))
    monkeypatch.setattr(dl, 'run_action', lambda a: 0)
    dl.main(['stop', '999999'])
    assert slept[0] <= 60.0


def test_run_action_stop(monkeypatch):
    calls = []
    import vnc_remote_secure.core.service_manager as sm
    monkeypatch.setattr(sm, 'stop_all',
                        lambda: calls.append('stop') or {'landing': True})
    assert dl.run_action('stop') == 0
    assert calls == ['stop']


def test_run_action_start(monkeypatch):
    called = []
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.core.service_manager as sm
    import vnc_remote_secure.security.profiles as prof
    monkeypatch.setattr(lc, 'startup', lambda: called.append('startup'))
    monkeypatch.setattr(prof, 'get_blocking_findings', lambda: [])
    monkeypatch.setattr(sm, 'start_all',
                        lambda: called.append('start') or {'vnc': 1})
    assert dl.run_action('start') == 0
    assert 'startup' in called and 'start' in called


def test_run_action_start_refused_on_blockers(monkeypatch):
    import vnc_remote_secure.core.lifecycle as lc
    import vnc_remote_secure.security.profiles as prof
    monkeypatch.setattr(lc, 'startup', lambda: None)
    monkeypatch.setattr(prof, 'get_blocking_findings',
                        lambda: [{'code': 'X', 'message': 'blocked'}])
    assert dl.run_action('start') == 1
