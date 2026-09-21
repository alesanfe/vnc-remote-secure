"""Unit tests for vendor/d3des — VNC DES password obfuscation.

VNC's stored-password format is DES-ECB over the password (truncated/
zero-padded to 8 bytes) under a FIXED key — not DES keyed by the
password itself, and with UltraVNC's fixedkey already bit-reversed
(the historical d3des ``deskey`` reverses internally; pycryptodome
does not). These tests pin that contract plus the bit-reversal math
against independently-computed pycryptodome output.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.vendor import d3des  # noqa: E402

pytest.importorskip('Crypto.Cipher.DES')

from Crypto.Cipher import DES  # noqa: E402

# ---------------------------------------------------------------------------
# _bit_reverse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('inp,expected', [
    (0x00, 0x00),
    (0x01, 0x80),
    (0x80, 0x01),
    (0xFF, 0xFF),
    (0xE8, 0x17),   # UltraVNC fixedkey byte 0: 0x17 bit-reversed = 0xE8
    (0x4A, 0x52),   # UltraVNC fixedkey byte 1: 0x52 → 0x4A
    (0x12, 0x48),
    (0xA5, 0xA5),
])
def test_bit_reverse_reference_values(inp, expected):
    assert d3des._bit_reverse(inp) == expected


def test_bit_reverse_is_involution():
    for b in range(256):
        assert d3des._bit_reverse(d3des._bit_reverse(b)) == b


# ---------------------------------------------------------------------------
# deskey / desfunc
# ---------------------------------------------------------------------------

def test_deskey_reverses_each_byte():
    key = bytes([0x17, 0x52, 0x6B, 0x06, 0x23, 0x4E, 0x58, 0x07])
    processed, decrypt = d3des.deskey(key, False)
    assert processed == bytes(d3des._bit_reverse(b) for b in key)
    assert processed == d3des.VNC_PASSWD_FIXED_KEY


def test_desfunc_matches_pycryptodome_ecb():
    """desfunc(deskey(k)) == DES-ECB encrypt under bit-reversed key."""
    key = bytes(range(8))
    data = b'12345678'
    processed, _ = d3des.deskey(key, False)
    expected = DES.new(processed, DES.MODE_ECB).encrypt(data)
    assert d3des.desfunc(data, (processed, False)) == expected


# ---------------------------------------------------------------------------
# encrypt_vnc_password
# ---------------------------------------------------------------------------

def test_encrypt_password_is_8_bytes_deterministic():
    a = d3des.encrypt_vnc_password('hunter2!')
    b = d3des.encrypt_vnc_password('hunter2!')
    assert len(a) == 8
    assert a == b


def test_encrypt_password_truncates_to_8_chars():
    """VNC auth only uses the first 8 chars — the blob must not
    change for characters beyond position 8."""
    a = d3des.encrypt_vnc_password('abcdefgh')
    b = d3des.encrypt_vnc_password('abcdefghEXTRA')
    assert a == b


def test_encrypt_password_pads_short_password():
    a = d3des.encrypt_vnc_password('abc')
    expected = DES.new(
        d3des.VNC_PASSWD_FIXED_KEY, DES.MODE_ECB).encrypt(b'abc\x00\x00\x00\x00\x00')
    assert a == expected


def test_encrypt_password_matches_fixed_key_not_self_key():
    """The blob must be DES(password) under VNC_PASSWD_FIXED_KEY —
    the classic bug is DES keyed BY the password, which no VNC
    server can validate. Pin the correct construction."""
    blob = d3des.encrypt_vnc_password('password')
    correct = DES.new(
        d3des.VNC_PASSWD_FIXED_KEY, DES.MODE_ECB).encrypt(b'password')
    # The wrong construction for contrast:
    wrong = DES.new(
        b'password', DES.MODE_ECB).encrypt(b'password')
    assert blob == correct
    assert blob != wrong


def test_encrypt_password_differs_per_password():
    assert d3des.encrypt_vnc_password('aaaaaaaa') != \
        d3des.encrypt_vnc_password('bbbbbbbb')
