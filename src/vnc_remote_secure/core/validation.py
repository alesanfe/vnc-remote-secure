"""Input validation utilities for VNC Remote Secure.

These functions enforce the security policies (password strength, port
ranges, reserved usernames, path traversal prevention, etc.) for the
Python-canonical runtime.
"""
import html
import re

from vnc_remote_secure.core.constants import (
    MIN_PASSWORD_LENGTH,
    RESERVED_USERNAMES,
    WEAK_PASSWORD_PATTERNS,
    WEAK_PASSWORDS,
)

# Pre-compiled regular expressions (kept module-level for reuse).
# The domain pattern uses nested quantifiers, but validate_domain()
# rejects input longer than 253 chars before matching, so worst-case
# backtracking is bounded and cannot be abused for ReDoS.
_DOMAIN_RE = re.compile(  # noqa: DUO138 - input length-capped at caller
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
)
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
_PORT_RE = re.compile(r'^[0-9]+$')

# Well-known ports that may conflict with system services.
_WELL_KNOWN_PORTS = {22, 80, 443, 3389, 5900, 5901}

# Common invalid email domains rejected for production use.
_INVALID_EMAIL_DOMAINS = {"example.com", "test.com", "invalid.com"}

# Weak password substrings (case-insensitive) — centralized in constants.py.
_WEAK_PATTERNS = WEAK_PASSWORD_PATTERNS


class ValidationError(ValueError):
    """Raised when input fails validation."""


def validate_port(port, field_name='port'):
    """Validate that ``port`` is a valid TCP/UDP port number.

    Returns the port as an ``int`` on success and raises
    :class:`ValidationError` on failure. Privileged and well-known ports
    only produce warnings via the module logger; they are still accepted.
    """
    if not isinstance(port, (int, str)) or isinstance(port, bool):
        raise ValidationError(f"{field_name}: Port must be a number")
    port_str = str(port)
    if not _PORT_RE.match(port_str):
        raise ValidationError(f"{field_name}: Port must be a number")
    port_int = int(port_str)
    if port_int < 1 or port_int > 65535:
        raise ValidationError(f"{field_name}: Port must be between 1 and 65535")
    if port_int < 1024:
        _warn(f"Port {port_int} is privileged and may require root permissions")
    if port_int in _WELL_KNOWN_PORTS:
        _warn(f"Port {port_int} is well-known and may conflict with system services")
    return port_int


def validate_password(password, field_name='password', min_length=None):
    """Validate password strength.

    Enforces minimum length, rejects weak/common passwords, and requires
    at least one uppercase, lowercase, digit, and special character.
    """
    if min_length is None:
        min_length = MIN_PASSWORD_LENGTH
    if not isinstance(password, str):
        raise ValidationError(f"{field_name}: Password must be a string")
    # Control characters (CR/LF/tab) must never reach backends that
    # consume passwords in line formats — ``chpasswd`` reads
    # ``user:pass\n`` records, so a newline would inject extra lines.
    if any(c in password for c in '\r\n\t\x00'):
        raise ValidationError(
            f"{field_name}: Password cannot contain control characters")
    if len(password) < min_length:
        raise ValidationError(
            f"{field_name}: Password must be at least {min_length} characters"
        )

    lowered = password.lower()
    for pattern in _WEAK_PATTERNS:
        if pattern in lowered:
            raise ValidationError(f"{field_name}: Password is too common and weak")
    if password in WEAK_PASSWORDS:
        raise ValidationError(f"{field_name}: Password is too common and weak")

    if not re.search(r'[A-Z]', password):
        raise ValidationError(
            f"{field_name}: Password must contain at least one uppercase letter"
        )
    if not re.search(r'[a-z]', password):
        raise ValidationError(
            f"{field_name}: Password must contain at least one lowercase letter"
        )
    if not re.search(r'[0-9]', password):
        raise ValidationError(f"{field_name}: Password must contain at least one digit")
    if not re.search(r'[^a-zA-Z0-9]', password):
        raise ValidationError(
            f"{field_name}: Password must contain at least one special character"
        )
    return True


def validate_domain(domain, field_name='domain'):
    """Validate a domain name. Empty values are allowed (SSL disabled)."""
    if not domain:
        return True
    if not isinstance(domain, str):
        raise ValidationError(f"{field_name}: Invalid domain name format")
    if len(domain) > 253:
        raise ValidationError(
            f"{field_name}: Domain name too long (max 253 characters)"
        )
    if domain in ('localhost', '127.0.0.1', '::1'):
        _warn("Using localhost domain may cause SSL certificate issues")
        return True
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"{field_name}: Invalid domain name format")
    return True


def validate_email(email, field_name='email'):
    """Validate an email address and reject header-injection attempts."""
    if not email:
        raise ValidationError(f"{field_name}: Email cannot be empty")
    if not isinstance(email, str):
        raise ValidationError(f"{field_name}: Email contains invalid characters")
    if re.search(r'\s', email):
        raise ValidationError(f"{field_name}: Email contains invalid characters")
    if not _EMAIL_RE.match(email):
        raise ValidationError(f"{field_name}: Invalid email format")
    if len(email) > 254:
        raise ValidationError(f"{field_name}: Email address too long")
    domain_part = email.rsplit('@', 1)[-1].lower()
    if domain_part in _INVALID_EMAIL_DOMAINS:
        raise ValidationError(
            f"{field_name}: Email domain {domain_part} is not valid "
            "for production"
        )
    return True


def validate_username(username, field_name='username'):
    """Validate a username against format, length, and reserved names."""
    if not username:
        raise ValidationError(f"{field_name}: Username cannot be empty")
    if not isinstance(username, str):
        raise ValidationError(
            f"{field_name}: Username can only contain letters, numbers, "
            "underscores, and hyphens"
        )
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            f"{field_name}: Username can only contain letters, numbers, "
            "underscores, and hyphens"
        )
    if len(username) < 3:
        raise ValidationError(f"{field_name}: Username must be at least 3 characters")
    if len(username) > 32:
        raise ValidationError(f"{field_name}: Username too long (max 32 characters)")
    if username in RESERVED_USERNAMES:
        raise ValidationError(
            f"{field_name}: Username '{username}' is reserved by the system"
        )
    if username[0].isdigit() or username[0] == '-':
        raise ValidationError(
            f"{field_name}: Username cannot start with a number or hyphen"
        )
    return True


def sanitize_input(value):
    """Escape dangerous HTML characters to prevent XSS.

    Replaces ``<``, ``>``, ``"`` and ``'`` with their HTML entity
    equivalents.
    """
    if value is None:
        return ''
    return html.escape(str(value), quote=True)


def _warn(message):
    """Emit a validation warning without pulling in a hard logging dep."""
    import logging
    logging.getLogger('vnc_remote_secure.validation').warning(message)
