"""Unit tests for security.credentials module."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.credentials import verify_password


def test_verify_password_werkzeug_hash():
    """verify_password accepts werkzeug-style hashes."""
    try:
        from werkzeug.security import generate_password_hash
    except ImportError:
        return
    h = generate_password_hash("Str0ng!Pass")
    assert verify_password("Str0ng!Pass", h) is True
    assert verify_password("wrong", h) is False


def test_verify_password_pbkdf2_hash():
    """verify_password accepts pbkdf2:iterations$salt$hash format."""
    import hashlib
    salt = "somesalt"
    iterations = 260000
    dk = hashlib.pbkdf2_hmac('sha256', b"Str0ng!Pass", salt.encode('utf-8'), iterations)
    h = f"pbkdf2:{iterations}${salt}${dk.hex()}"
    assert verify_password("Str0ng!Pass", h) is True
    assert verify_password("wrong", h) is False


def test_verify_password_empty_hash():
    """verify_password returns False for empty hash."""
    assert verify_password("anything", "") is False


class TestVerifyPasswordBoundaries:
    def test_iteration_cap_rejects_dos(self):
        """iterations > 10M must fail fast — the self-DoS guard."""
        from vnc_remote_secure.security.credentials import verify_password
        assert verify_password(
            'x', 'pbkdf2:20000000$salt$00' * 1) is False

    def test_zero_iterations_rejected(self):
        from vnc_remote_secure.security.credentials import verify_password
        assert verify_password('x', 'pbkdf2:0$c2FsdA==$00') is False

    def test_malformed_pbkdf2_rejected(self):
        from vnc_remote_secure.security.credentials import verify_password
        for bad in ('pbkdf2:notanint$s$h', 'pbkdf2:1000', 'pbkdf2:',
                    'pbkdf2:1000$salt$zzzz'):
            assert verify_password('x', bad) is False

    def test_unknown_scheme_rejected(self):
        from vnc_remote_secure.security.credentials import verify_password
        assert verify_password('x', 'md5$deadbeef') is False
