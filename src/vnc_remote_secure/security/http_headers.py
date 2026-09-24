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
# Note: 'unsafe-inline' is retained for script-src because the templates
# use inline event handlers; 'unsafe-eval' is removed to prevent eval().
# connect-src is restricted to 'self' and the same-origin WebSocket
# schemes (wss/ws) which are required for the noVNC/terminal connections.
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' wss: ws:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def _safe_header_value(value: str, fallback: str) -> str:
    """Return ``value`` unless it contains CR/LF (header injection).

    Operator-supplied env values land verbatim in response headers; a
    malformed value must fall back to the safe default rather than
    break or poison the response.
    """
    if value and '\r' not in value and '\n' not in value:
        return value
    return fallback


def get_security_headers(tls_enabled: bool = True) -> dict:
    """Return the security headers to apply to a response.

    Args:
        tls_enabled: Whether TLS is active. When True, HSTS is included.

    Returns:
        Dict of header name -> value.
    """
    headers = dict(DEFAULT_SECURITY_HEADERS)

    # Content-Security-Policy (allow override via env). CR/LF is
    # rejected the same way SESSION_SAMESITE is validated: the
    # http.server fallback does not escape header values, so a raw
    # env-supplied policy could inject extra response headers.
    csp = os.environ.get('CSP_POLICY', DEFAULT_CSP)
    headers['Content-Security-Policy'] = _safe_header_value(csp, DEFAULT_CSP)

    # HSTS only when TLS is enabled (never send HSTS over HTTP).
    if tls_enabled:
        hsts = os.environ.get(
            'HSTS_HEADER',
            TLS_SECURITY_HEADERS['Strict-Transport-Security'],
        )
        headers['Strict-Transport-Security'] = _safe_header_value(
            hsts, TLS_SECURITY_HEADERS['Strict-Transport-Security'])

    return headers


def send_security_headers(handler, tls_enabled=None) -> None:
    """Emit all security headers on a ``BaseHTTPRequestHandler``.

    Call inside an ``end_headers()`` override so every response —
    including error responses — carries the headers::

        def end_headers(self):
            send_security_headers(self)
            super().end_headers()

    Args:
        handler: The request handler (must have ``send_header``).
        tls_enabled: Whether this response is served over TLS (adds
            HSTS). When ``None`` (default) it is auto-detected from
            the accepted connection: services wrapping their listen
            socket with an SSLContext produce ``ssl.SSLSocket``
            children, so plain-HTTP services keep emitting no HSTS
            while TLS services do — with no per-service plumbing.
    """
    if tls_enabled is None:
        import ssl
        tls_enabled = isinstance(
            getattr(handler, 'connection', None), ssl.SSLSocket)
    # Skip header names the handler already emitted explicitly — a
    # route that sets a stricter CSP (e.g. /share running
    # script-src 'self') must not get a second, looser policy header;
    # browsers AND duplicate CSPs, but the explicit one should win
    # cleanly rather than rely on intersection semantics.
    emitted = {
        line.split(b':', 1)[0].strip().lower()
        for line in getattr(handler, '_headers_buffer', None) or []
        if isinstance(line, bytes)}
    for name, value in get_security_headers(tls_enabled).items():
        if name.lower().encode() not in emitted:
            handler.send_header(name, value)
