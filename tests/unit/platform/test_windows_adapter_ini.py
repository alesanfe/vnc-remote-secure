"""Unit tests for _merge_ini_overrides (ultravnc.ini rewrite)."""
from vnc_remote_secure.platform.windows.adapter import _merge_ini_overrides


def test_admin_keys_rewritten():
    lines = ['[admin]', 'PortNumber=5900', 'KeepMe=1']
    out = _merge_ini_overrides(lines, {'PortNumber': '5901'})
    assert 'PortNumber=5901' in out
    assert 'KeepMe=1' in out


def test_credential_keys_rewritten_in_every_section():
    """A stale passwd in [ultravnc]/[poll] must not survive."""
    lines = [
        '[admin]', 'passwd=OLD',
        '[ultravnc]', 'passwd=STALE', 'other=1',
        '[poll]', 'passwd2=STALE2',
    ]
    out = _merge_ini_overrides(
        lines, {'passwd': 'AA', 'passwd2': 'BB'})
    assert out.count('passwd=AA') == 2  # [admin] + [ultravnc]
    assert 'passwd2=BB' in out
    assert 'passwd=STALE' not in out
    assert 'other=1' in out


def test_missing_keys_inserted_under_admin():
    lines = ['[admin]', 'PortNumber=5900', '[ultravnc]', 'x=1']
    out = _merge_ini_overrides(lines, {'NewKey': '9'})
    admin_idx = out.index('[admin]')
    assert out[admin_idx + 1] == 'NewKey=9'
    # Not inserted into [ultravnc]
    assert out.index('x=1') > out.index('NewKey=9')


def test_non_admin_structural_keys_untouched():
    lines = ['[admin]', 'A=1', '[other]', 'A=2']
    out = _merge_ini_overrides(lines, {'A': 'X'})
    assert out == ['[admin]', 'A=X', '[other]', 'A=2']


def test_empty_input_adds_admin_section():
    out = _merge_ini_overrides([], {'PortNumber': '5900'})
    assert '[admin]' in out
    assert 'PortNumber=5900' in out


def test_lines_without_equals_skipped_not_corrupted():
    lines = ['[admin]', 'garbage-no-equals', 'A=1']
    out = _merge_ini_overrides(lines, {})
    assert 'garbage-no-equals' in out or 'A=1' in out
    # no exception, output is a list of strings
    assert all(isinstance(ln, str) for ln in out)


def test_override_value_cannot_inject_lines():
    """A value containing a newline must not split into a second
    key=value line — INI injection vector via config."""
    out = _merge_ini_overrides(
        ['[admin]', 'A=1'], {'K': 'v\nMalicious=1'})
    # No standalone 'Malicious=1' line may appear — the newline must be
    # stripped, collapsing the payload into the K= value.
    assert 'Malicious=1' not in out
    assert any(ln.startswith('K=') and '\n' not in ln for ln in out)
