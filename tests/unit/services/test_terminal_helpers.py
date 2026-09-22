"""Unit tests for terminal.py's pure helpers.

Covers the pieces of the web terminal that don't need a live
WebSocket: tab completion (command + path, with traversal confinement
and control-char rejection), child-env sanitization, subprocess argv
building, builtin output texts and origin checking.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services.terminal import (  # noqa: E402
    COMMON_COMMANDS,
    _build_child_env,
    _build_subprocess_args,
    _clear_text,
    _complete_path_glob,
    _complete_windows_command,
    _help_text,
    _history_text,
    _interrupt_text,
    _is_origin_allowed,
)

# ---------------------------------------------------------------------------
# _complete_windows_command
# ---------------------------------------------------------------------------


def test_complete_command_matches_prefix():
    """'ec' completes to echo (COMMON_COMMANDS) — 'where' may add
    PATH executables that don't share the prefix, so only assert the
    builtin match is present and results are strings."""
    suggestions = _complete_windows_command('ec')
    assert 'echo' in suggestions
    assert all(isinstance(s, str) and s for s in suggestions)


def test_complete_command_empty_prefix_returns_all():
    suggestions = _complete_windows_command('')
    assert set(suggestions) >= set(COMMON_COMMANDS)


def test_complete_command_no_match():
    assert _complete_windows_command('zzz_no_such_cmd_zzz') == []


# ---------------------------------------------------------------------------
# _complete_path_glob
# ---------------------------------------------------------------------------

def test_path_glob_completes_files(tmp_path):
    (tmp_path / 'alpha.txt').write_text('x')
    (tmp_path / 'alps.txt').write_text('x')
    (tmp_path / 'beta').mkdir()
    suggestions = _complete_path_glob('cat al', str(tmp_path))
    assert 'alpha.txt' in suggestions
    assert 'alps.txt' in suggestions
    assert 'beta' not in suggestions  # does not match prefix 'al'


def test_path_glob_dirs_get_trailing_sep(tmp_path):
    (tmp_path / 'subdir').mkdir()
    suggestions = _complete_path_glob('cd sub', str(tmp_path))
    assert 'subdir' + os.sep in suggestions


def test_path_glob_rejects_control_chars(tmp_path):
    """Null bytes / control characters return None (rejected input)."""
    assert _complete_path_glob('cat \x00evil', str(tmp_path)) is None
    assert _complete_path_glob('cat \x01', str(tmp_path)) is None


def test_path_glob_confines_to_cwd(tmp_path):
    """An absolute path outside cwd falls back to cwd — the completion
    must not enumerate arbitrary directories."""
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret.txt').write_text('x')
    cwd = tmp_path / 'jail'
    cwd.mkdir()
    (cwd / 'jailfile.txt').write_text('x')
    suggestions = _complete_path_glob(
        'cat ' + str(outside / 'sec'), str(cwd))
    # Falls back to searching inside cwd — 'sec*' matches nothing there
    # or only cwd files; crucially it must not return 'secret.txt'.
    assert 'secret.txt' not in (suggestions or [])


# ---------------------------------------------------------------------------
# _build_child_env
# ---------------------------------------------------------------------------

def test_child_env_strips_secret_vars(monkeypatch):
    """Credential vars must not reach the spawned shell."""
    from vnc_remote_secure.security.redaction import SECRET_VARS
    for var in list(SECRET_VARS)[:5]:
        monkeypatch.setenv(var, 'supersecret')
    monkeypatch.setenv('HARMLESS_VAR', 'visible')
    env = _build_child_env()
    for var in SECRET_VARS:
        assert var not in env
    assert env['HARMLESS_VAR'] == 'visible'


# ---------------------------------------------------------------------------
# _build_subprocess_args
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != 'nt', reason='Windows cmd.exe path')
def test_build_args_cmd_windows():
    args = _build_subprocess_args('dir', 'cmd.exe', 'C:\\')
    assert args[-2] == '/c'
    assert args[-1] == 'dir'
    assert 'cmd' in args[0].lower()


@pytest.mark.skipif(os.name != 'nt', reason='Windows powershell path')
def test_build_args_powershell_windows():
    args = _build_subprocess_args('Get-Item x', 'powershell.exe', 'C:\\')
    joined = ' '.join(args)
    assert '-NoProfile' in joined
    assert '-NonInteractive' in joined
    assert args[-1] == 'Get-Item x'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX shell path')
def test_build_args_posix():
    args = _build_subprocess_args('ls -la', 'bash', '/tmp')
    assert args[-2] == '-c'
    assert args[-1] == 'ls -la'


# ---------------------------------------------------------------------------
# Builtin texts
# ---------------------------------------------------------------------------

def test_help_text_mentions_builtins():
    text = _help_text()
    assert 'history' in text
    assert 'help' in text


def test_history_text_empty():
    assert 'No commands' in _history_text([])


def test_history_text_lists_commands():
    text = _history_text(['dir', 'echo hi'])
    assert 'dir' in text
    assert 'echo hi' in text


def test_clear_and_interrupt_texts_are_ansi():
    assert '\x1b[' in _clear_text()
    assert _interrupt_text()


# ---------------------------------------------------------------------------
# _is_origin_allowed
# ---------------------------------------------------------------------------

def test_origin_empty_rejected():
    assert _is_origin_allowed('') is False


def test_origin_localhost_port_allowed(monkeypatch):
    """An origin on a configured local service port is allowed."""
    monkeypatch.setenv('NOVNC_PORT', '6080')
    assert _is_origin_allowed('http://127.0.0.1:6080') is True


def test_origin_evil_rejected():
    assert _is_origin_allowed('https://evil.example.com') is False
