"""Unit tests for MFA (TOTP) module."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.mfa import (
    generate_totp_secret,
    generate_totp_uri,
    verify_totp,
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
    is_mfa_enabled,
    mfa_required_for_login,
)


class TestTOTPSecret:
    def test_generates_base32_secret(self):
        secret = generate_totp_secret()
        assert isinstance(secret, str)
        assert len(secret) == 32  # 20 bytes -> 32 base32 chars

    def test_secrets_are_unique(self):
        s1 = generate_totp_secret()
        s2 = generate_totp_secret()
        assert s1 != s2

    def test_uri_format(self):
        secret = generate_totp_secret()
        uri = generate_totp_uri(secret, 'admin')
        assert uri.startswith('otpauth://totp/')
        assert 'secret=' + secret in uri
        assert 'issuer=VNC+Remote+Secure' in uri


class TestTOTPVerification:
    def test_valid_code_accepted(self):
        secret = generate_totp_secret()
        # Generate a valid TOTP code
        from vnc_remote_secure.security.mfa import _hotp, TOTP_INTERVAL
        step = int(time.time()) // TOTP_INTERVAL
        code = f"{_hotp(secret.encode() if isinstance(secret, bytes) else __import__('base64').b32decode(secret + '=' * ((8 - len(secret) % 8) % 8)), step):06d}"
        assert verify_totp(secret, code)

    def test_invalid_code_rejected(self):
        secret = generate_totp_secret()
        assert not verify_totp(secret, '000000')

    def test_wrong_length_rejected(self):
        secret = generate_totp_secret()
        assert not verify_totp(secret, '12345')
        assert not verify_totp(secret, '1234567')

    def test_non_numeric_rejected(self):
        secret = generate_totp_secret()
        assert not verify_totp(secret, 'abcdef')

    def test_empty_rejected(self):
        secret = generate_totp_secret()
        assert not verify_totp(secret, '')

    def test_window_allows_drift(self):
        secret = generate_totp_secret()
        from vnc_remote_secure.security.mfa import _hotp, TOTP_INTERVAL, _base32_decode
        key = _base32_decode(secret)
        now = int(time.time())
        step = now // TOTP_INTERVAL
        # Previous step should be accepted (within window)
        code = f"{_hotp(key, step - 1):06d}"
        assert verify_totp(secret, code, timestamp=now)


class TestRecoveryCodes:
    def test_generates_correct_count(self):
        codes = generate_recovery_codes(8)
        assert len(codes) == 8

    def test_format_is_XXXX_XXXX(self):
        codes = generate_recovery_codes(4)
        for c in codes:
            assert len(c) == 9  # XXXX-XXXX
            assert c[4] == '-'

    def test_hash_is_sha256(self):
        h = hash_recovery_code('ABCD-1234')
        assert len(h) == 64  # SHA-256 hex

    def test_verify_valid_recovery_code(self):
        codes = generate_recovery_codes(4)
        hashes = [hash_recovery_code(c) for c in codes]
        assert verify_recovery_code(codes[0], hashes)

    def test_verify_invalid_recovery_code(self):
        hashes = [hash_recovery_code('AAAA-BBBB')]
        assert not verify_recovery_code('CCCC-DDDD', hashes)

    def test_verify_empty_rejected(self):
        assert not verify_recovery_code('', ['somehash'])

    def test_codes_are_unique(self):
        codes = generate_recovery_codes(20)
        assert len(set(codes)) == 20


class TestMFAConfig:
    def test_mfa_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        monkeypatch.delenv('MFA_REQUIRED', raising=False)
        assert not is_mfa_enabled()
        assert not mfa_required_for_login()

    def test_mfa_enabled_when_secret_set(self, monkeypatch):
        monkeypatch.setenv('TOTP_SECRET', generate_totp_secret())
        assert is_mfa_enabled()
        assert mfa_required_for_login()

    def test_mfa_required_when_flag_set(self, monkeypatch):
        monkeypatch.delenv('TOTP_SECRET', raising=False)
        monkeypatch.setenv('MFA_REQUIRED', 'true')
        assert mfa_required_for_login()
