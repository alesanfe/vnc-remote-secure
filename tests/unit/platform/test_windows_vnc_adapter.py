"""Unit tests for the Windows adapter UltraVNC ini rendering.

Verifies ``_write_ultravnc_ini`` produces a valid ``ultravnc.ini`` —
the actual configuration mechanism UltraVNC uses in file-settings
mode (``UseRegistry=0``) — and that the DES password is written in
the classic vncpasswd format.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'src'))

from vnc_remote_secure.platform.windows.adapter import WindowsAdapter
from vnc_remote_secure.vendor.d3des import encrypt_vnc_password

# Real vector taken from a shipped ultravnc.ini/registry Password
# value: the plaintext 'vnc12345' obfuscates to C688664E275EA400 under
# the fixed VNC key. The earlier value F50F904B11EE3F7C came from this
# project's own (double bit-reversed) encoder — UltraVNC rejects it.
KNOWN_VECTOR = ('vnc12345', 'C688664E275EA400')


def test_encrypt_vnc_password_matches_real_ini_vector():
    """The stored form must match the real vncpasswd/ultravnc.ini format."""
    password, expected_hex = KNOWN_VECTOR
    assert encrypt_vnc_password(password).hex().upper() == expected_hex


def test_write_ultravnc_ini_creates_admin_section(tmp_path):
    """A missing ini is created with [admin] and all managed keys."""
    exe = tmp_path / 'winvnc.exe'
    exe.write_text('fake')
    WindowsAdapter._write_ultravnc_ini(str(exe), 'secret1')
    text = (tmp_path / 'ultravnc.ini').read_text()
    assert '[admin]' in text
    assert 'UseRegistry=0' in text
    assert 'QueryAccept=0' in text
    assert 'AuthRequired=1' in text
    assert 'PortNumber=' in text
    assert 'HTTPPortNumber=' in text
    blob = encrypt_vnc_password('secret1')
    checksum = sum(blob) & 0xFF
    # GetPrivateProfileStruct format: 8 hex bytes + 1 checksum byte.
    assert f"passwd={blob.hex().upper()}{checksum:02X}" in text


def test_write_ultravnc_ini_preserves_unmanaged_keys(tmp_path):
    """Keys the app doesn't manage keep their values."""
    exe = tmp_path / 'winvnc.exe'
    exe.write_text('fake')
    (tmp_path / 'ultravnc.ini').write_text(
        '[admin]\n'
        'passwd=F50F904B11EE3F7C\n'
        'DisableTrayIcon=1\n'
        'FileTransferEnabled=0\n'
        '[ultravnc]\n'
        'passwd=F50F904B11EE3F7C\n'
        'primary=1\n'
        'secondary=0\n')
    WindowsAdapter._write_ultravnc_ini(str(exe), 'newpass1')
    text = (tmp_path / 'ultravnc.ini').read_text()
    new_hex = encrypt_vnc_password('newpass1').hex().upper()
    # Unmanaged keys preserved.
    assert 'DisableTrayIcon=1' in text
    assert 'FileTransferEnabled=0' in text
    assert 'primary=1' in text
    assert 'secondary=0' in text
    # Every passwd entry rewritten — no stale credential survives in
    # any section ([admin], [ultravnc], ...).
    assert 'F50F904B11EE3F7C' not in text
    assert text.count(f'passwd={new_hex}') >= 2


def test_write_ultravnc_ini_without_password_keeps_structure(tmp_path):
    """An empty password still renders the structural overrides."""
    exe = tmp_path / 'winvnc.exe'
    exe.write_text('fake')
    WindowsAdapter._write_ultravnc_ini(str(exe), '')
    text = (tmp_path / 'ultravnc.ini').read_text()
    assert 'QueryAccept=0' in text
    assert 'passwd=' not in text


def test_vnc_des_truncates_to_8_chars():
    """VNC DES uses only the first 8 password bytes — pin the protocol
    limitation so a 'fix' that hashes the full password breaks loudly."""
    assert (encrypt_vnc_password('abcdefghXYZ').hex().upper()
            == encrypt_vnc_password('abcdefgh').hex().upper())


def test_encrypt_empty_password_deterministic():
    blob = encrypt_vnc_password('')
    assert len(blob) == 8  # DES block
    assert blob == encrypt_vnc_password('')
