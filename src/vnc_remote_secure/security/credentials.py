"""Credential management for VNC Remote Secure.

Password verification for the werkzeug-compatible hash formats this
project historically produced/consumed — ``pbkdf2:method:iters$salt$hex``
and ``scrypt:N:r:p$salt$hex`` — plus the current format,
``$argon2id$`` PHC strings via argon2-cffi. New hashes are Argon2id;
legacy formats verify but get rehashed on the next successful login.
"""
import hashlib
import hmac
import re

# argon2 PHC strings embed their memory/time/parallelism params —
# a forged stored hash with m=4GB would turn verify into self-DoS.
# Cap the declared parameters before handing them to argon2-cffi.
_ARGON2_PARAM_RE = re.compile(
    r'^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$')
_ARGON2_MAX_MIB = 512
_ARGON2_MAX_TIME = 16
_ARGON2_MAX_PAR = 8


def _verify_argon2(password, stored_hash):
    """Verify an ``$argon2id$`` PHC string with bounded params."""
    m = _ARGON2_PARAM_RE.match(stored_hash)
    if not m:
        return False
    mem_kib, time_cost, par = (int(g) for g in m.groups())
    if (mem_kib > _ARGON2_MAX_MIB * 1024
            or not 1 <= time_cost <= _ARGON2_MAX_TIME
            or not 1 <= par <= _ARGON2_MAX_PAR):
        return False
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import (
            InvalidHashError,
            VerificationError,
            VerifyMismatchError,
        )
    except ImportError:
        return False
    try:
        return bool(PasswordHasher().verify(stored_hash, password))
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def _verify_pbkdf2(password, stored_hash):
    """Verify ``pbkdf2:method:iterations$salt$hex`` (and the bare
    ``pbkdf2:iterations$salt$hex`` legacy form)."""
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


def _verify_scrypt(password, stored_hash):
    """Verify werkzeug-style ``scrypt:N:r:p$salt$hex`` hashes via
    stdlib ``hashlib.scrypt``."""
    body = stored_hash[len('scrypt:'):]
    params_str, rest = body.split('$', 1)
    salt, expected_hex = rest.split('$', 1)
    n_str, r_str, p_str = params_str.split(':')
    n, r, p = int(n_str), int(r_str), int(p_str)
    # Bound the memory/CPU cost — scrypt is memory-hard by design, so
    # a forged stored hash must not turn verification into a DoS.
    # 128*n*r is the working buffer: n*r <= 2^21 keeps it <= 256 MiB.
    if n < 2 or n & (n - 1) or n > 2 ** 20 or not 1 <= r <= 32 \
            or not 1 <= p <= 32 or n * r > 2 ** 21:
        return False
    dk = hashlib.scrypt(password.encode('utf-8'),
                        salt=salt.encode('utf-8'),
                        n=n, r=r, p=p,
                        # OpenSSL's default 32 MiB cap rejects
                        # werkzeug's own default params (32768:8:1 ≈
                        # 33.5 MiB) — give the bounded worst case.
                        maxmem=512 * 1024 * 1024)
    return hmac.compare_digest(
        dk.hex().encode('ascii'),
        expected_hex.encode('utf-8', 'replace'))


def verify_password(password, stored_hash):
    """Verify ``password`` against a ``stored_hash`` in constant time.

    Supports ``$argon2id$`` PHC strings (the current format) and the
    legacy ``pbkdf2:``/``scrypt:`` werkzeug formats stored deployments
    may still carry.
    """
    if not stored_hash:
        return False
    try:
        if stored_hash.startswith('$argon2'):
            return _verify_argon2(password, stored_hash)
        if stored_hash.startswith('pbkdf2:'):
            return _verify_pbkdf2(password, stored_hash)
        if stored_hash.startswith('scrypt:'):
            return _verify_scrypt(password, stored_hash)
    except (ValueError, KeyError):
        return False
    return False
