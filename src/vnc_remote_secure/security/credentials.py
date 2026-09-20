"""Credential management for VNC Remote Secure.

Password verification supporting ``werkzeug.security`` hashes (the same
library used by the existing Flask UI) with a ``hashlib.pbkdf2`` fallback
so the module has no hard external dependency.
"""
import hashlib
import hmac


def verify_password(password, stored_hash):
    """Verify ``password`` against a ``stored_hash`` in constant time.

    Supports both werkzeug-style hashes and ``pbkdf2`` format hashes
    (``pbkdf2:method:iterations$salt$hash`` or the bare
    ``pbkdf2:iterations$salt$hash``).
    """
    if not stored_hash:
        return False
    try:
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_hash, password)
    except (ImportError, ValueError):
        pass
    if not stored_hash.startswith('pbkdf2:'):
        return False
    # Parse the werkzeug format ``pbkdf2:method:iterations$salt$hash``
    # (e.g. ``pbkdf2:sha256:600000$salt$hex``) and the bare legacy form
    # ``pbkdf2:iterations$salt$hash``.
    try:
        body = stored_hash[len('pbkdf2:'):]
        iterations_str, rest = body.split('$', 1)
        salt, expected_hex = rest.split('$', 1)
        if ':' in iterations_str:
            method, iterations_str = iterations_str.rsplit(':', 1)
        else:
            method = 'sha256'
        iterations = int(iterations_str)
        # Cap iterations: a malformed/misconfigured stored hash with a
        # huge count would hang the auth thread computing pbkdf2
        # (self-DoS). 10M is far above any sane deployment value.
        if iterations < 1 or iterations > 10_000_000:
            return False
        dk = hashlib.pbkdf2_hmac(method, password.encode('utf-8'),
                                 salt.encode('utf-8'), iterations)
        # expected_hex comes from stored config — compare as bytes so a
        # non-ASCII value fails closed rather than raising TypeError.
        return hmac.compare_digest(
            dk.hex().encode('ascii'),
            expected_hex.encode('utf-8', 'replace'))
    except (ValueError, KeyError):
        return False
