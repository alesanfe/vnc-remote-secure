"""SecureHttpClient (httpx + DNS pinning) tests — mock transports.

The egress wrapper keeps three invariants: URL vetting before
connect, single request (no redirects), bounded response size, and
one tenacity retry on transport failures.
"""
import httpx
import pytest

pytestmark = pytest.mark.timeout(30)


def test_secure_post_delivers_body(monkeypatch):
    from vnc_remote_secure.security import http_client
    monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_PRIVATE', 'true')
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(204)

    status = http_client.secure_post(
        'https://hook.example.test/wh', b'{"a":1}',
        {'Content-Type': 'application/json'},
        transport=httpx.MockTransport(handler))
    assert status == 204
    assert calls and calls[0].content == b'{"a":1}'


def test_secure_post_status_passthrough(monkeypatch):
    """A 4xx/5xx answer is the receiver's call — returned, not
    retried (retries would duplicate the alert)."""
    from vnc_remote_secure.security import http_client
    monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_PRIVATE', 'true')
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503)

    status = http_client.secure_post(
        'https://hook.example.test/wh', b'x', {},
        transport=httpx.MockTransport(handler))
    assert status == 503
    assert calls == [1]  # no retry on status


def test_secure_post_retries_transport_error_once(monkeypatch):
    """Connect failures retry once (tenacity), then raise."""
    from vnc_remote_secure.security import http_client
    monkeypatch.setenv('ALERT_WEBHOOK_ALLOW_PRIVATE', 'true')
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError('boom', request=request)

    with pytest.raises(httpx.ConnectError):
        http_client.secure_post(
            'https://hook.example.test/wh', b'x', {},
            transport=httpx.MockTransport(handler))
    assert calls == [1, 1]


def test_validate_url_rejects_private_by_default(monkeypatch):
    from vnc_remote_secure.security import http_client
    monkeypatch.delenv('ALERT_WEBHOOK_ALLOW_PRIVATE', raising=False)
    assert http_client.validate_url('https://192.168.1.5/wh') is not None
    assert http_client.validate_url('file:///etc/passwd') is not None
    assert http_client.validate_url('https:///missing-host') is not None


def test_pinned_transport_dials_validated_ip(monkeypatch):
    """The pinned connect must use the vetted IP, not re-resolve —
    that would reopen the DNS-rebinding window."""
    import socket

    from vnc_remote_secure.security import http_client
    dialed = {}
    monkeypatch.setattr(
        socket, 'getaddrinfo',
        lambda *a, **k: [(socket.AF_INET, 0, 0, '',
                          ('93.184.216.34', 443))])

    class _FakeResp:
        status = 200
        reason = 'OK'

        def getheaders(self):
            return []

        def read(self, amt=None):
            return b''

    class _FakeConn:
        def __init__(self, ip, hostname, port, context, timeout):
            dialed['ip'] = ip
            dialed['sni'] = hostname

        def request(self, method, path, body=None, headers=None):
            dialed['path'] = path

        def getresponse(self):
            return _FakeResp()

        def close(self):
            pass

    monkeypatch.setattr(
        http_client, '_PinnedHTTPSConnection', _FakeConn)
    status = http_client.secure_post(
        'https://example.com/hook', b'{}', {})
    assert status == 200
    assert dialed['ip'] == '93.184.216.34'
    # SNI/Host still carry the real hostname for TLS verification.
    assert dialed['sni'] == 'example.com'


def test_pinned_transport_refuses_no_public_addr(monkeypatch):
    """If resolution yields no global address at connect time the
    request is refused — re-resolution to private can't connect."""
    import socket

    from vnc_remote_secure.security import http_client
    monkeypatch.setattr(
        socket, 'getaddrinfo',
        lambda *a, **k: [(socket.AF_INET, 0, 0, '', ('10.0.0.5', 443))])
    with pytest.raises(httpx.ConnectError):
        http_client.secure_post(
            'https://internal/hook', b'{}', {})


def test_pinned_transport_no_redirect(monkeypatch):
    """A 302 is the answer, not a chase — the transport issues
    exactly one request and never follows Location."""
    import socket

    from vnc_remote_secure.security import http_client
    requests = []
    monkeypatch.setattr(
        socket, 'getaddrinfo',
        lambda *a, **k: [(socket.AF_INET, 0, 0, '',
                          ('93.184.216.34', 443))])

    class _FakeResp:
        status = 302
        reason = 'Found'

        def getheaders(self):
            return [('Location', 'https://evil.internal/')]

        def read(self, amt=None):
            return b''

    class _FakeConn:
        def __init__(self, *a, **k):
            pass

        def request(self, method, path, body=None, headers=None):
            requests.append((method, path))

        def getresponse(self):
            return _FakeResp()

        def close(self):
            pass

    monkeypatch.setattr(
        http_client, '_PinnedHTTPSConnection', _FakeConn)
    status = http_client.secure_post(
        'https://example.com/hook', b'{}', {})
    assert status == 302
    assert requests == [('POST', '/hook')]
