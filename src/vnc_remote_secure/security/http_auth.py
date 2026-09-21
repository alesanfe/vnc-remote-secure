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

from vnc_remote_secure.core.config import load_env_file

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
    trusted = os.environ.get('TRUSTED_PROXY', 'false').lower() in (
        'true', '1', 'yes')
    # XFF is only meaningful when the request actually came through the
    # trusted proxy. Honoring it for any peer lets a client that can
    # reach a service port directly spoof its identity — rotating
    # rate-limit keys and bypassing allowed_ip session binding. The
    # peer must be loopback (nginx on the same host) or listed in
    # TRUSTED_PROXY_IPS (comma-separated, e.g. an off-box proxy).
    if trusted and headers is not None and peer_ip:
        proxy_ips = {'127.0.0.1', '::1', 'localhost'}
        extra = os.environ.get('TRUSTED_PROXY_IPS', '')
        proxy_ips.update(p.strip() for p in extra.split(',') if p.strip())
        if peer_ip not in proxy_ips:
            return peer_ip
        get = getattr(headers, 'get', None)
        if callable(get):
            forwarded = get('X-Forwarded-For', '')
            if forwarded:
                # Take the LAST entry, not the first: nginx appends the
                # real peer ($proxy_add_x_forwarded_for) after any
                # client-supplied XFF, so the first hop is attacker-
                # controlled and the last is the trusted-proxy-set one.
                return forwarded.split(',')[-1].strip()
    return peer_ip


def _is_locked(limiter, client_ip):
    """True when the client is locked out in ANY shared namespace.

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


def check_terminal_auth(auth_header, client_ip=None):
    """Check terminal auth using ``TTYD_USERNAME`` / ``TTYD_PASSWD`` or
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
    """True when ``host`` resolves to a loopback-only bind."""
    return (host or '').strip() in (
        '127.0.0.1', '::1', 'localhost', '127.0.0.0/8')


def _loopback_peer(client_ip) -> bool:
    """True when the request's socket peer is loopback."""
    import ipaddress
    try:
        return ipaddress.ip_address(
            (client_ip or '').strip()).is_loopback
    except ValueError:
        return (client_ip or '').strip() in ('localhost',)


def check_health_auth(auth_header, client_ip=None, peer_ip=None):
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
    """
    load_env_file()
    token = os.environ.get('HEALTH_AUTH_TOKEN', '')
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
    return check_bearer_token(auth_header, token)


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
