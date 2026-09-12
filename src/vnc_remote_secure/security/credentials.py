"""Credential management for VNC Remote Secure.

Password generation, strength validation, and hashing/verification.
Hashing uses ``werkzeug.security`` when available (the same library
used by the existing Flask UI) and falls back to ``hashlib.pbkdf2`` so
the module has no hard external dependency.
"""
import hashlib
import hmac
import secrets
import string

from vnc_remote_secure.core.constants import MIN_PASSWORD_LENGTH, WEAK_PASSWORDS
from vnc_remote_secure.core.validation import validate_password


def generate_password(length=16):
    """Generate a cryptographically strong random password.

    The character set includes letters, digits, and a safe subset of
    special characters, guaranteeing the result passes
    :func:`validate_password_strength`.
    """
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*'
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if validate_password_strength(password):
            return password


def validate_password_strength(password):
    """Return ``True`` if ``password`` meets the strength policy.

    Wraps :func:`vnc_remote_secure.core.validation.validate_password`
    and additionally rejects the known weak passwords from
    :data:`WEAK_PASSWORDS`.
    """
    if password in WEAK_PASSWORDS:
        return False
    try:
        return validate_password(password, min_length=MIN_PASSWORD_LENGTH)
    except ValueError:
        return False


def hash_password(password):
    """Hash ``password`` using a salted key-derivation function.

    Returns a string in the format ``pbkdf2:iterations$salt$hash`` that
    can be verified by :func:`verify_password`. When ``werkzeug`` is
    available its ``generate_password_hash`` is used instead for
    compatibility with the Flask UI.
    """
    try:
        from werkzeug.security import generate_password_hash
        return generate_password_hash(password)
    except ImportError:
        pass
    iterations = 260000
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                             salt.encode('utf-8'), iterations)
    return f"pbkdf2:{iterations}${salt}${dk.hex()}"


def verify_password(password, stored_hash):
    """Verify ``password`` against a ``stored_hash`` in constant time.

    Supports both werkzeug-style hashes and the ``pbkdf2`` format
    produced by :func:`hash_password`.
    """
    if not stored_hash:
        return False
    try:
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_hash, password)
    except ImportError:
        pass
    if not stored_hash.startswith('pbkdf2:'):
        return False
    # Parse pbkdf2:iterations$salt$hash
    try:
        body = stored_hash[len('pbkdf2:'):]
        iterations_str, rest = body.split('$', 1)
        salt, expected_hex = rest.split('$', 1)
        iterations = int(iterations_str)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                 salt.encode('utf-8'), iterations)
        return hmac.compare_digest(dk.hex(), expected_hex)
    except (ValueError, KeyError):
        return False
