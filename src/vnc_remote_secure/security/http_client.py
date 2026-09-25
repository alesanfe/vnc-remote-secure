"""Outbound HTTP client with SSRF policy and DNS pinning.

All egress HTTP in the product goes through this wrapper — never
``urllib``/``requests`` directly. Two layers defend the egress path:

1. ``validate_url`` runs BEFORE connect — scheme allowlist, optional
   private-address opt-out, and (default) every resolved address must
   be public unicast.
2. ``PinnedTransport`` dials the exact IP that passed the check —
   a hostile resolver cannot re-answer with a private address between
   validation and connect (DNS-rebinding window closed). TLS still
   verifies the real hostname (SNI + cert chain).

Redirects are never followed: a webhook must go where the operator
pointed it — following would bounce an HMAC-signed POST to whatever
the redirector chooses, reopening SSRF after destination vetting.
"""
import http.client
import ipaddress
import logging
import socket
import ssl
from urllib.parse import urlparse

import httpx
import tenacity

from vnc_remote_secure.core.config import env_flag

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
# Webhook responses are status codes, not payloads — cap the body so a
# hostile endpoint cannot fill memory with a multi-GB reply.
MAX_RESPONSE_BYTES = 256 * 1024

_RETRY = tenacity.retry(
    stop=tenacity.stop_after_attempt(2),
    wait=tenacity.wait_random(0.3, 1.0),
    # Only transport failures are retried — an HTTP status is the
    # receiver's intentional answer, not a transient error.
    retry=tenacity.retry_if_exception_type(
        (httpx.TransportError, OSError)),
    reraise=True)


def _resolve_addrs(hostname: str) -> list:
    """Resolve ``hostname`` to address strings ([] on failure)."""
    try:
        return [
            sockaddr[0]
            for _fam, _typ, _proto, _canon, sockaddr
            in socket.getaddrinfo(hostname, None)
        ]
    except OSError:
        return []


def _resolved_addrs_public(hostname: str) -> bool:
    """True only if EVERY resolved address is a public IP.

    A single private/loopback/link-local/CGNAT/reserved address in the
    answer is enough to reject — the pinned connect may pick any of
    them.
    """
    addrs = _resolve_addrs(hostname)
    if not addrs:
        return False
    for addr in addrs:
        try:
            if not ipaddress.ip_address(addr).is_global:
                return False
        except ValueError:
            return False
    return True


def validate_url(url: str,
                 allow_http_env: str = 'ALERT_WEBHOOK_ALLOW_HTTP',
                 allow_private_env: str =
                 'ALERT_WEBHOOK_ALLOW_PRIVATE') -> str | None:
    """Return an error string, or None when the URL is safe to POST to.

    Default policy: HTTPS only, public unicast destinations only.
    ``ALERT_WEBHOOK_ALLOW_HTTP=true`` and
    ``ALERT_WEBHOOK_ALLOW_PRIVATE=true`` are explicit opt-outs for
    operators running a receiver on the LAN.
    """
    try:
        p = urlparse(url)
    except ValueError:
        return 'unparseable URL'
    if p.scheme == 'http' and not env_flag(allow_http_env):
        return f'http:// requires {allow_http_env}=true'
    if p.scheme not in ('https', 'http'):
        return f'disallowed scheme {p.scheme!r}'
    if not p.hostname:
        return 'no hostname'
    if not env_flag(allow_private_env):
        if not _resolved_addrs_public(p.hostname):
            return 'resolves to a non-public address'
    return None


def redact_url(url: str) -> str:
    """Log-safe form of a webhook URL (scheme + host only).

    Webhook URLs embed their credential in the path (e.g. Discord's
    ``/api/webhooks/<id>/<token>``) or in the query string. A generic
    webhook may carry the token as the FIRST path segment, so showing
    even one segment can leak the secret — redact the whole path.
    """
    try:
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}/…'
    except ValueError:
        return '<invalid-url>'


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a validated IP but TLS-verifies the
    real hostname — DNS pinning without breaking SNI/cert checks."""

    def __init__(self, ip, hostname, port, context, timeout):
        super().__init__(ip, port=port, timeout=timeout,
                         context=context)
        self._sni_host = hostname

    def connect(self):
        sock = socket.create_connection(
            (self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self._sni_host)


class PinnedTransport(httpx.BaseTransport):
    """httpx transport that dials the IP validated as public.

    Bypasses httpx's connection pool on purpose: pooling would keep a
    connection whose peer address was never re-vetted. Each request is
    a fresh DNS-pinned connection — exactly one request, no redirects.
    """

    def __init__(self, allow_private: bool = False,
                 timeout: float = DEFAULT_TIMEOUT):
        self._allow_private = allow_private
        self._timeout = timeout

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        host = url.host
        port = url.port or (443 if url.scheme == 'https' else 80)
        path = url.raw_path.decode('ascii', 'replace')
        if self._allow_private:
            dial = host
        else:
            try:
                dial = next(
                    (a for a in _resolve_addrs(host)
                     if ipaddress.ip_address(a).is_global), None)
            except ValueError:
                dial = None
            if dial is None:
                raise httpx.ConnectError(
                    'no public address for pinned connect',
                    request=request)
        if url.scheme == 'https':
            conn = _PinnedHTTPSConnection(
                dial, host, port, ssl.create_default_context(),
                self._timeout)
        else:
            conn = http.client.HTTPConnection(
                dial, port, timeout=self._timeout)
        try:
            conn.request(request.method, path,
                         body=request.read(),
                         headers=dict(request.headers))
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise httpx.ReadError(
                    'response exceeds MAX_RESPONSE_BYTES',
                    request=request)
            return httpx.Response(
                resp.status,
                headers=httpx.Headers(resp.getheaders()),
                content=data,
                request=request)
        finally:
            conn.close()


def secure_client(*, allow_private: bool = False,
                  timeout: float = DEFAULT_TIMEOUT,
                  transport: httpx.BaseTransport | None = None
                  ) -> httpx.Client:
    """An httpx.Client with the pinned transport and no redirects.

    ``transport`` is injectable for tests (respx.MockTransport).
    """
    return httpx.Client(
        transport=transport or PinnedTransport(allow_private=allow_private,
                                               timeout=timeout),
        follow_redirects=False,
        timeout=timeout)


def secure_request(method: str, url: str, *,
                   body: bytes | None = None,
                   headers: dict | None = None,
                   allow_private_env: str = 'ALERT_WEBHOOK_ALLOW_PRIVATE',
                   timeout: float = DEFAULT_TIMEOUT,
                   transport: httpx.BaseTransport | None = None
                   ) -> httpx.Response:
    """Issue one pinned request; returns the httpx.Response.

    Retries once on transport failure (tenacity). Status codes are
    the receiver's answer — never retried.
    """
    allow_private = env_flag(allow_private_env)

    @_RETRY
    def _attempt() -> httpx.Response:
        with secure_client(allow_private=allow_private,
                           timeout=timeout,
                           transport=transport) as client:
            return client.request(method, url, content=body,
                                  headers=headers or {})

    return _attempt()


def secure_post(url: str, body: bytes, headers: dict,
                *, allow_private_env: str = 'ALERT_WEBHOOK_ALLOW_PRIVATE',
                timeout: float = DEFAULT_TIMEOUT,
                transport: httpx.BaseTransport | None = None) -> int:
    """POST ``body`` to ``url``; returns the HTTP status code.

    Retries once on transport failure (tenacity). Callers decide what
    a status means — this layer only guarantees the request reached a
    vetted, pinned destination.
    """
    return secure_request(
        'POST', url, body=body, headers=headers,
        allow_private_env=allow_private_env, timeout=timeout,
        transport=transport).status_code
