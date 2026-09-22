"""Unit tests for MFA (TOTP) module."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.mfa import (
    generate_recovery_codes,
    generate_totp_secret,
    generate_totp_uri,
    hash_recovery_code,
    is_mfa_enabled,
    mfa_required_for_login,
    verify_recovery_code,
    verify_totp,
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
        from vnc_remote_secure.security.mfa import TOTP_INTERVAL, _hotp
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

    def test_non_ascii_digits_rejected_without_crash(self):
        """Unicode digits pass str.isdigit() but must fail closed —
        str-form hmac.compare_digest raises TypeError on non-ASCII."""
        secret = generate_totp_secret()
        # Arabic-Indic and full-width digits: isdigit()==True, not ASCII
        assert not verify_totp(secret, '١٢٣٤٥٦')
        assert not verify_totp(secret, '１２３４５６')
        assert not verify_totp(secret, None)
        assert not verify_totp(secret, 123456)  # non-str input

    def test_window_allows_drift(self):
        secret = generate_totp_secret()
        from vnc_remote_secure.security.mfa import (
            TOTP_INTERVAL,
            _base32_decode,
            _hotp,
            _record_step,
        )
        key = _base32_decode(secret)
        now = int(time.time())
        step = now // TOTP_INTERVAL
        # Reset anti-replay state so earlier tests' consumed counters
        # (same process, shared backend) do not mask the drift check.
        _record_step(step - 3)
        # Previous step should be accepted (within window)
        code = f"{_hotp(key, step - 1):06d}"
        assert verify_totp(secret, code, timestamp=now)

    def test_totp_replay_rejected(self):
        """A code at an already-consumed counter is rejected — a captured
        TOTP cannot be replayed inside its validity window."""
        secret = generate_totp_secret()
        from vnc_remote_secure.security.mfa import (
            TOTP_INTERVAL,
            _base32_decode,
            _hotp,
            _record_step,
        )
        key = _base32_decode(secret)
        now = int(time.time())
        step = now // TOTP_INTERVAL
        _record_step(step - 3)  # clean slate
        code = f"{_hotp(key, step):06d}"
        assert verify_totp(secret, code, timestamp=now)
        # Same code, same step: replay must fail.
        assert not verify_totp(secret, code, timestamp=now)
        # An older (drift-window) code after the newer one was consumed
        # also fails — counters may only move forward.
        old = f"{_hotp(key, step - 1):06d}"
        assert not verify_totp(secret, old, timestamp=now)


class TestRecoveryCodes:
    def test_generates_correct_count(self):
        codes = generate_recovery_codes(8)
        assert len(codes) == 8

    def test_format_is_XXXX_XXXX_XXXX(self):
        codes = generate_recovery_codes(4)
        for c in codes:
            assert len(c) == 14  # XXXX-XXXX-XXXX
            assert c[4] == '-'
            assert c[9] == '-'

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


class TestTotpStepClaim:
    """_claim_step: the cross-process atomic replay barrier."""

    def test_same_step_claimed_once(self):
        from vnc_remote_secure.security.mfa import _claim_step
        secret = generate_totp_secret()
        step = int(time.time() // 30)
        assert _claim_step(secret, step) is True
        assert _claim_step(secret, step) is False  # replay denied

    def test_different_step_allowed(self):
        from vnc_remote_secure.security.mfa import _claim_step
        secret = generate_totp_secret()
        step = int(time.time() // 30)
        assert _claim_step(secret, step + 5000) is True
        assert _claim_step(secret, step + 5001) is True

    def test_different_secret_same_step_allowed(self):
        """Different users share timesteps — claim key is per-secret."""
        from vnc_remote_secure.security.mfa import _claim_step
        step = int(time.time() // 30) + 9000
        assert _claim_step('AAAA', step) is True
        assert _claim_step('BBBB', step) is True
