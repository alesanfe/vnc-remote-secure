"""Custom exceptions for VNC Remote Secure."""


class VncRemoteError(Exception):
    """Base exception for all VNC Remote Secure errors."""


class ServiceError(VncRemoteError):
    """Raised when a service fails to start or stop."""


class SecurityError(VncRemoteError):
    """Raised when a security policy violation is detected."""
