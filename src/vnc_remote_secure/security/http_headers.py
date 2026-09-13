"""HTTP security headers for VNC Remote Secure.

Provides a set of security headers that should be applied to all HTTP
responses. These headers protect against common web vulnerabilities:

- ``Strict-Transport-Security``: Enforces HTTPS (HSTS)
- ``X-Frame-Options``: Prevents clickjacking
- ``X-Content-Type-Options``: Prevents MIME sniffing
- ``Content-Security-Policy``: Restricts resource loading
- ``Referrer-Policy``: Controls referrer information
- ``Permissions-Policy``: Restricts browser features
- ``X-XSS-Protection``: Legacy XSS protection (for older browsers)
"""
import os
from typing import Dict

# Default security headers applied to all responses.
DEFAULT_SECURITY_HEADERS = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'X-XSS-Protection': '1; mode=block',
}

# Additional headers when TLS is enabled.
TLS_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
}

# CSP policy (configurable via CSP_POLICY env var).
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' wss: ws:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def get_security_headers(tls_enabled: bool = True) -> Dict:
    """Return the security headers to apply to a response.

    Args:
        tls_enabled: Whether TLS is active. When True, HSTS is included.

    Returns:
        Dict of header name -> value.
    """
    headers = dict(DEFAULT_SECURITY_HEADERS)

    # Content-Security-Policy (allow override via env).
    csp = os.environ.get('CSP_POLICY', DEFAULT_CSP)
    headers['Content-Security-Policy'] = csp

    # HSTS only when TLS is enabled (never send HSTS over HTTP).
    if tls_enabled:
        hsts = os.environ.get(
            'HSTS_HEADER',
            TLS_SECURITY_HEADERS['Strict-Transport-Security'],
        )
        headers['Strict-Transport-Security'] = hsts

    return headers


def apply_security_headers(response, tls_enabled: bool = True):
    """Apply security headers to an HTTP response object.

    Works with both Flask response objects and http.server responses.

    Args:
        response: The response object to modify.
        tls_enabled: Whether TLS is active.
    """
    headers = get_security_headers(tls_enabled)

    # Flask response objects have a ``headers`` dict-like interface.
    if hasattr(response, 'headers'):
        if hasattr(response.headers, '__setitem__'):
            # Flask/Werkzeug response.
            for name, value in headers.items():
                response.headers[name] = value
        elif hasattr(response.headers, 'update'):
            # http.server BaseHTTPRequestHandler (end_headers path).
            for name, value in headers.items():
                response.headers.update({name: value})

    return response


def security_headers_handler(handler_class):
    """Decorator that adds security headers to an http.server handler.

    Usage:
        @security_headers_handler
        class MyHandler(http.server.BaseHTTPRequestHandler):
            ...
    """
    original_end_headers = handler_class.end_headers

    def end_headers(self):
        from vnc_remote_secure.security.profiles import _is_tls_enabled
        tls = _is_tls_enabled()
        headers = get_security_headers(tls)
        for name, value in headers.items():
            self.send_header(name, value)
        original_end_headers(self)

    handler_class.end_headers = end_headers
    return handler_class
