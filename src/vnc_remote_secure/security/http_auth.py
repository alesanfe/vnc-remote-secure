"""Shared HTTP authentication helpers for VNC Remote Secure services.

Provides Basic-auth and Bearer-token validation plus a Flask decorator
so that landing, terminal, health, and the Flask UI use a single auth
model instead of each service implementing its own.
"""
import base64
import functools
import hmac
import logging
import os

from vnc_remote_secure.core.config import env_flag, load_env_file

logger = logging.getLogger(__name__)


def check_basic_auth(auth_header, expected_username, expected_password):
    """Validate an ``Authorization: Basic <b64>`` header.

    Returns ``True`` if the decoded ``username:password`` matches the
    expected credentials (constant-time comparison).
    """
    if not auth_header or not auth_header.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        expected = f'{expected_username}:{expected_password}'
        return hmac.compare_digest(decoded, expected)
    except Exception as exc:
        logger.warning("Basic auth check failed: %s", exc)
        return False


def check_bearer_token(auth_header, expected_token):
    """Validate an ``Authorization: Bearer <token>`` header.

    Returns ``True`` if the token matches (constant-time comparison).
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header[7:]
    # compare_digest on str rejects non-ASCII — the http.server header
    # decoder passes through any byte as a latin-1 char, so a fuzzed
    # Bearer value would raise TypeError instead of failing closed.
    try:
        return hmac.compare_digest(
            token.encode('utf-8', 'replace'),
            expected_token.encode('utf-8', 'replace'))
    except Exception:
        return False


def request_headers_safe(headers) -> bool:
    """Reject request-smuggling header shapes before body handling.

    ``http.server`` parses bodies only via ``Content-Length`` — it has
    no ``Transfer-Encoding`` support. A request carrying BOTH (or a
    duplicated Content-Length) is ambiguous: front proxies and this
    server can disagree on where the request ends, the classic TE/CL
    desync. nginx normalizes upstream traffic, but a direct client on
    the service port does not get that protection.

    Returns ``True`` when the headers are unambiguous.
    """
    get_all = getattr(headers, 'get_all', None)
    if get_all:
        if get_all('Transfer-Encoding'):
            return False
        cl = get_all('Content-Length')
        if cl is not None and len([v for v in cl if v.strip()]) > 1:
            return False
    else:
        if headers.get('Transfer-Encoding'):
            return False
    return True


def _peer_is_trusted_proxy(peer_ip: str, proxy_ips: set) -> bool:
    """Return True when ``peer_ip`` is an allowed proxy.

    Entries may be exact addresses or CIDR ranges (e.g. a corporate
    proxy pool ``10.0.0.0/24``). Malformed entries match nothing —
    a typo in TRUSTED_PROXY_IPS must not widen the trust set.
    """
    if peer_ip in proxy_ips:
        return True
    import ipaddress
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for entry in proxy_ips:
        if '/' not in entry:
            continue
        try:
            if peer in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip_from(headers, peer_ip):
    """Return the effective client IP for a request.

    Uses ``X-Forwarded-For`` only when ``TRUSTED_PROXY=true`` — behind
    nginx the socket peer is 127.0.0.1, so ``allowed_ip`` session
    restrictions and rate limiting must consult the forwarded header
    the trusted proxy sets. Without the flag the raw peer IP is
    returned (spoof-proof).

    Args:
        headers: request headers (anything with ``.get``).
        peer_ip: the socket peer address.
    """
    load_env_file()
    trusted = env_flag('TRUSTED_PROXY', 'false')
    # XFF is only meaningful when the request actually came through the
    # trusted proxy. Honoring it for any peer lets a client that can
    # reach a service port directly spoof its identity — rotating
    # rate-limit keys and bypassing allowed_ip session binding. The
    # peer must be loopback (nginx on the same host) or listed in
    # TRUSTED_PROXY_IPS (comma-separated exact IPs or CIDR ranges,
    # e.g. an off-box proxy or a proxy pool).
    if trusted and headers is not None and peer_ip:
        proxy_ips = {'127.0.0.1', '::1', 'localhost'}
        extra = os.environ.get('TRUSTED_PROXY_IPS', '')
        proxy_ips.update(p.strip() for p in extra.split(',') if p.strip())
        if not _peer_is_trusted_proxy(peer_ip, proxy_ips):
            return peer_ip
        get = getattr(headers, 'get', None)
        if callable(get):
            forwarded = get('X-Forwarded-For', '')
            if forwarded:
                # Take the LAST non-empty entry, not the first: nginx
                # appends the real peer ($proxy_add_x_forwarded_for)
                # after any client-supplied XFF, so the first hop is
                # attacker-controlled and the last is the trusted-proxy-
                # set one. A trailing comma ('1.2.3.4,') must not yield
                # an empty key — empty keys collapse into a shared
                # rate-limit bucket and can bypass allowed_ip binds.
                for hop in reversed(forwarded.split(',')):
                    hop = hop.strip()
                    if hop:
                        return hop
    return peer_ip


def cookie_value(cookie_header: str, name: str) -> str:
    """Extract one cookie value from a raw ``Cookie`` header.

    Returns ``''`` when the header is empty or the cookie is absent.
    Centralises the ``split(';') / strip / startswith`` loop that the
    WS auth paths used to re-implement per service.
    """
    if not cookie_header:
        return ''
    prefix = name + '='
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith(prefix):
            return part.split('=', 1)[1].strip()
    return ''


def header_get(headers, name: str, default: str = '') -> str:
    """Read a header value from anything with ``.get``, else default.

    WS handlers receive headers as dicts, Tornado header objects, or
    tuples — each used to re-implement
    ``headers.get(k, d) if hasattr(headers, 'get') else d``.
    """
    get = getattr(headers, 'get', None)
    if callable(get):
        return get(name, default)
    return default


def extract_bearer_token(auth_header: str) -> str:
    """Return the Bearer credential from an Authorization header.

    Case-insensitive scheme match; ``''`` when absent. Validation is
    separate — see :func:`check_bearer_token`.
    """
    if auth_header and auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()
    return ''


def ws_peer_ip(websocket) -> str:
    """Return the peer IP of a ``websockets`` connection (``''`` if none).

    ``remote_address`` is ``(host, port)`` or ``None`` for closed/local
    transports — every WS service used to inline the
    ``ws.remote_address[0] if ws.remote_address else None`` ternary.
    """
    addr = getattr(websocket, 'remote_address', None)
    return addr[0] if addr else ''


def _is_locked(limiter, client_ip):
    """Return True when the client is locked out in ANY shared namespace.

    ``attempt_login`` records failures under ``ip:{addr}`` while the
    Basic-auth helpers historically used the bare address — a login
    lockout therefore did not protect the Basic-auth surfaces that
    verify the same credentials. Check both so one shared credential
    gets one shared lockout budget.
    """
    return (limiter.is_locked(client_ip)
            or limiter.is_locked(f'ip:{client_ip}'))


def check_landing_auth(auth_header, client_ip=None):
    """Check landing-page auth using ``LANDING_PASSWORD`` (username ``admin``).

    Returns ``True`` when the credentials match. An empty configured
    password denies access (fail-closed): the portal exposes
    operational details (service inventory, LAN IPs, metrics) and on
    Windows it may bind a public interface — the startup blocker
    refuses to run with an empty LANDING_PASSWORD anyway, so the
    fail-open path must not exist for directly-launched services.

    Args:
        auth_header: The ``Authorization`` header value.
        client_ip: When provided, failures and successes feed the
            shared auth rate limiter and locked IPs are rejected —
            the same brute-force protection the gateway applies to
            session-cookie auth.
    """
    load_env_file()
    password = os.environ.get('LANDING_PASSWORD', '')
    if not password:
        # Persisted auto-generated credential: get_config() writes it
        # to <run_dir>/generated_credentials.env — a process that did
        # not run get_config() would otherwise deny every request.
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )
            password = _load_generated_credential('LANDING_PASSWORD')
        except Exception:  # noqa: BLE001 - fallback is best-effort
            password = ''
    if not password:
        return False  # fail-closed: no password => no access
    limiter = None
    if client_ip:
        from vnc_remote_secure.security.rate_limit import get_auth_limiter
        limiter = get_auth_limiter()
        if _is_locked(limiter, client_ip):
            return False
    ok = check_basic_auth(auth_header, 'admin', password)
    if limiter is not None:
        if ok:
            limiter.record_success(client_ip)
        else:
            limiter.record_failure(client_ip)
    return ok


def authenticate_landing(auth_header, client_ip=None):
    """Authenticate a portal operator; return ``(ok, operator)``.

    Like :func:`check_landing_auth` but returns the operator record
    so callers can enforce per-role permissions:

    - A username found in the operator store authenticates against
      it (and only it — a stored user does NOT fall back to the env
      password, which would silently widen their credentials).
    - Any other username takes the env ``admin``/``LANDING_PASSWORD``
      bootstrap path and maps to the ``admin`` role.

    ``operator`` is ``None`` on failure, else ``{'username', 'role',
    'permissions'}``. The rate limiter records exactly one outcome
    per attempt.
    """
    limiter = None
    if client_ip:
        from vnc_remote_secure.security.rate_limit import get_auth_limiter
        limiter = get_auth_limiter()
        if _is_locked(limiter, client_ip):
            return False, None
    username = None
    password = None
    if auth_header.startswith('Basic '):
        try:
            decoded = base64.b64decode(
                auth_header[6:]).decode('utf-8', 'replace')
            username, _, password = decoded.partition(':')
        except ValueError:
            username = None
    if username:
        try:
            from vnc_remote_secure.security.operator_users import load_store, verify
            if username in load_store():
                rec = verify(username, password or '')
                if limiter is not None:
                    (limiter.record_success if rec else
                     limiter.record_failure)(client_ip)
                return (True, rec) if rec else (False, None)
        except Exception as exc:  # noqa: BLE001 - store failure falls back to env
            # A corrupt/unreadable store must not 500 the request —
            # but silently bypassing RBAC must be visible.
            logger.warning(
                "Operator store unreadable (%s) — falling back to "
                "env credentials", exc)
    ok = check_landing_auth(auth_header, client_ip=None)
    if limiter is not None:
        (limiter.record_success if ok else
         limiter.record_failure)(client_ip)
    if not ok:
        return False, None
    return True, {
        'username': 'admin', 'role': 'admin',
        'permissions': ['admin:*'],
    }


def check_terminal_auth(auth_header, client_ip=None):
    """Check terminal auth using ``TTYD_USERNAME`` / ``TTYD_PASSWD`` or.

    an ephemeral Bearer token with the ``terminal:use`` permission.
    """
    load_env_file()
    # Accept ephemeral Bearer tokens (used by session create --no-terminal
    # restrictions and per-action authorization).
    if auth_header.startswith('Bearer '):
        from vnc_remote_secure.security.ephemeral_sessions import check_permission
        # Same rate-limit gate as the Basic path below — without it the
        # Bearer surface is an unthrottled check_permission oracle (and
        # probes can burn a captured single-use token).
        if client_ip:
            from vnc_remote_secure.security.rate_limit import get_auth_limiter
            limiter = get_auth_limiter()
            if _is_locked(limiter, client_ip):
                return False
            ok = check_permission(
                auth_header[7:].strip(), 'terminal:use', resource='terminal',
                client_ip=client_ip)
            if ok:
                limiter.record_success(client_ip)
            else:
                limiter.record_failure(client_ip)
            return ok
        return check_permission(
            auth_header[7:].strip(), 'terminal:use', resource='terminal',
            client_ip=client_ip)
    from vnc_remote_secure.core.constants import DEFAULT_TTYD_USERNAME
    username = os.environ.get('TTYD_USERNAME', DEFAULT_TTYD_USERNAME)
    password = os.environ.get('TTYD_PASSWD', '')
    if not password:
        # Persisted auto-generated credential: get_config() writes it
        # to <run_dir>/generated_credentials.env — a process that did
        # not run get_config() would otherwise reject a valid login.
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )
            password = _load_generated_credential('TTYD_PASSWD')
        except Exception:  # noqa: BLE001 - fallback is best-effort
            password = ''
    if not password:
        return False
    # Feed the shared auth limiter like check_landing_auth — otherwise
    # the terminal's Basic-auth endpoint is an unthrottled password
    # brute-force oracle.
    limiter = None
    if client_ip:
        from vnc_remote_secure.security.rate_limit import get_auth_limiter
        limiter = get_auth_limiter()
        if _is_locked(limiter, client_ip):
            return False
    ok = check_basic_auth(auth_header, username, password)
    if limiter is not None:
        if ok:
            limiter.record_success(client_ip)
        else:
            limiter.record_failure(client_ip)
    return ok


def _loopback_bind(host: str) -> bool:
    """Return True when ``host`` resolves to a loopback-only bind."""
    return (host or '').strip() in (
        '127.0.0.1', '::1', 'localhost', '127.0.0.0/8')


def _loopback_peer(client_ip) -> bool:
    """Return True when the request's socket peer is loopback."""
    import ipaddress
    try:
        return ipaddress.ip_address(
            (client_ip or '').strip()).is_loopback
    except ValueError:
        return (client_ip or '').strip() in ('localhost',)


def check_health_auth(auth_header, client_ip=None, peer_ip=None,
                      scope=None):
    """Check health endpoint auth using optional ``HEALTH_AUTH_TOKEN``.

    Returns ``True`` if no token is configured — but ONLY when every
    host these endpoints can bind is loopback AND the request's socket
    peer is itself loopback. The bind check alone is not enough: any
    operator-added reverse proxy (not just the shipped nginx.conf,
    which denies non-loopback) in front of the loopback port would
    otherwise expose ``/audit``, ``/metrics`` and service state to the
    network. ``peer_ip`` is the real socket peer (``client_address`` /
    ``remote_addr``) — it must NOT come from X-Forwarded-For, which a
    direct client can spoof when TRUSTED_PROXY is set. ``client_ip``
    is only used as a fallback when no peer is available.

    ``scope`` ('audit'/'metrics') enables credential separation: when
    ``AUDIT_AUTH_TOKEN``/``METRICS_AUTH_TOKEN`` is set, ONLY that
    scoped token authenticates the scope — the general
    ``HEALTH_AUTH_TOKEN`` no longer reaches it. With the scoped var
    unset, the general token still works (backward compatible).
    """
    load_env_file()
    token = os.environ.get('HEALTH_AUTH_TOKEN', '')
    scope_env = {'audit': 'AUDIT_AUTH_TOKEN',
                 'metrics': 'METRICS_AUTH_TOKEN'}.get(scope)
    if scope_env:
        scoped_token = os.environ.get(scope_env, '')
        if scoped_token:
            token = scoped_token
    if not token:
        base = os.environ.get('BIND_HOST', '127.0.0.1')
        ui_host = os.environ.get('USER_UI_HOST', '') or base
        health_host = os.environ.get('HEALTH_WEB_HOST', '') or base
        if _loopback_bind(ui_host) and _loopback_bind(health_host):
            peer = peer_ip if peer_ip is not None else client_ip
            if peer is None or _loopback_peer(peer):
                return True  # Open access is safe: loopback only.
            logger.warning(
                "Health request from non-loopback peer %s with no "
                "HEALTH_AUTH_TOKEN — denying", peer)
            return False
        logger.warning(
            "HEALTH_AUTH_TOKEN unset but health endpoints bind "
            "non-loopback (%s, %s) — requiring Bearer auth",
            ui_host, health_host)
        return False  # fail-closed on public binds
    # Feed the shared auth limiter like the landing/terminal checkers —
    # otherwise the Bearer endpoints are an unthrottled token
    # brute-force oracle (only exploitable for a weak token, but the
    # limiter is nearly free). The raw peer is a fine limiter key when
    # the caller did not resolve an XFF client_ip.
    limiter_ip = client_ip or peer_ip
    limiter = None
    if limiter_ip:
        from vnc_remote_secure.security.rate_limit import get_auth_limiter
        limiter = get_auth_limiter()
        if _is_locked(limiter, limiter_ip):
            return False
    ok = check_bearer_token(auth_header, token)
    if limiter is not None:
        if ok:
            limiter.record_success(limiter_ip)
        else:
            limiter.record_failure(limiter_ip)
    return ok


def require_auth(check_func, scheme='Basic', realm='VNC Remote Secure'):
    """Flask decorator that requires authentication via ``check_func``.

    ``check_func`` receives the ``Authorization`` header value and
    returns ``True`` if access is allowed. On failure, returns a
    uniform JSON 401 response with ``WWW-Authenticate`` header.

    ``scheme`` selects the ``WWW-Authenticate`` challenge advertised to
    clients (e.g., ``'Bearer'`` for token-based health auth).

    Checkers that accept a ``client_ip`` keyword argument receive the
    request's remote address so they can feed the shared auth rate
    limiter; single-argument checkers are called as before.
    """
    import inspect
    params = inspect.signature(check_func).parameters
    wants_ip = 'client_ip' in params
    wants_peer = 'peer_ip' in params

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            from flask import request

            from vnc_remote_secure.core.errors import json_error
            auth = request.headers.get('Authorization', '')
            # Resolve the real client IP through X-Forwarded-For when
            # TRUSTED_PROXY is set — behind nginx, remote_addr is the
            # proxy (127.0.0.1), which would otherwise rate-limit and
            # audit-log the proxy instead of the actual client.
            real_ip = client_ip_from(request.headers, request.remote_addr)
            check_kwargs = {}
            if wants_ip:
                check_kwargs['client_ip'] = real_ip
            if wants_peer:
                # The raw socket peer — XFF-spoofable checks (loopback
                # gating) must use this, not the resolved real_ip.
                check_kwargs['peer_ip'] = request.remote_addr
            ok = check_func(auth, **check_kwargs)
            if not ok:
                resp, status = json_error('Unauthorized', 401)
                resp.headers['WWW-Authenticate'] = f'{scheme} realm="{realm}"'
                resp.status_code = status
                return resp
            return view(*args, **kwargs)
        return wrapper
    return decorator
