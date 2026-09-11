"""Custom exceptions for VNC Remote Secure."""


class VncRemoteError(Exception):
    """Base exception for all VNC Remote Secure errors."""


class ConfigurationError(VncRemoteError):
    """Raised when configuration is invalid or incomplete."""


class DependencyError(VncRemoteError):
    """Raised when a required system dependency is missing."""


class ServiceError(VncRemoteError):
    """Raised when a service fails to start or stop."""


class SecurityError(VncRemoteError):
    """Raised when a security policy violation is detected."""


class PlatformError(VncRemoteError):
    """Raised when a platform-specific operation fails."""
