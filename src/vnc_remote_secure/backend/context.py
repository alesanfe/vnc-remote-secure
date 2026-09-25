"""Transport-neutral request context for the landing/API surface.

All portal auth, session and CSRF logic lives here operating on a
small duck-typed interface:

- ``headers`` — case-insensitive mapping (``email.message.Message``
  from ``http.server``, ``starlette.datastructures.Headers`` from
  FastAPI/uvicorn — both expose ``.get(name, default)``).
- ``peer_ip()`` — socket peer IP.
- ``is_tls`` — whether the request arrived over TLS.
- ``rfile`` — ``io.BytesIO`` request body.
- ``send_response``/``send_header``/``end_headers``/``wfile`` — the
  response collector; :meth:`to_response` renders the ASGI answer.

``services.landing.LandingHandler`` (stdlib transport) subclasses this
context so the FastAPI adapter and the legacy handler share exactly
one implementation of the security surface.
"""
from __future__ import annotations

import io
import logging
import os
import time as _time

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.errors import log_exception
from vnc_remote_secure.security.http_auth import client_ip_from, cookie_value

logger = logging.getLogger(__name__)

# Directory holding the Vite build output (SPA bundle).
_ADMIN_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), '..', 'web', 'static', 'admin'))

_ADMIN_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.map': 'application/json',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
}


class PortalContext:
    """Request-scoped portal state + gate logic, transport-free.

    The subclass/adapter provides ``headers``, ``peer_ip()``,
    ``is_tls``, ``rfile`` and the response collector primitives
    (``send_response``, ``send_header``, ``end_headers``, ``wfile``).
    """

    # Operator session cookie lifetime (absolute).
    _OP_SESSION_TTL = 8 * 3600
    # Cap on simultaneous operator sessions per account — the oldest
    # is revoked when a new one is minted past the limit.
    _OP_SESSION_MAX_PER_USER = 10

    is_tls: bool = False

    # -- transport primitives the context relies on --------------------
    # These are provided by the concrete transport (stdlib handler or
    # the ASGI adapter). Declared for documentation; the subclass sets
    # them in __init__.

    def peer_ip(self) -> str:  # pragma: no cover - overridden
        return getattr(self, '_client_ip', '')

    def send_response(self, status: int) -> None:  # pragma: no cover
        raise NotImplementedError

    def send_header(self, name: str, value: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def end_headers(self) -> None:  # pragma: no cover
        raise NotImplementedError

    # -----------------------------------------------------------------
    # JSON helpers — same shapes the stdlib mixin produced
    # -----------------------------------------------------------------
    def send_body(self, status: int, body: str | bytes,
                  content_type: str):
        """Write a pre-serialized body with Content-Length set."""
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status: int = 200, indent=None):
        """Write ``payload`` as a JSON response (Content-Length set)."""
        import json
        body = json.dumps(payload, indent=indent).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json_error(self, message: str, status: int,
                        www_authenticate: str | None = None,
                        code: str | None = None):
        """Write a canonical ``error_json`` response."""
        from vnc_remote_secure.core.errors import error_json
        body_text, _ = error_json(message, status, code=code)
        body = body_text.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        if www_authenticate:
            self.send_header('WWW-Authenticate', www_authenticate)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -----------------------------------------------------------------
    # Portal identity (ephemeral share cookie | operator session/Basic)
    # -----------------------------------------------------------------
    def _ephemeral_cookie(self) -> str:
        """Extract the ``vnc_ephemeral`` cookie value, if present."""
        return cookie_value(
            self.headers.get('Cookie', ''), 'vnc_ephemeral')

    def _valid_ephemeral_cookie(self) -> bool:
        """Return True when the client holds an activated ephemeral session."""
        internal = self._ephemeral_cookie()
        if not internal:
            return False
        from vnc_remote_secure.security.ephemeral_sessions import check_session_permission
        # Portal access requires any valid permission; 'view' is the
        # base permission every role grants.
        client_ip = client_ip_from(
            self.headers,
            self.peer_ip())
        return check_session_permission(
            internal, 'view', client_ip=client_ip)

    def _portal_identity(self):
        """Resolve the portal request's auth identity.

        Returns ``(authenticated, operator)`` where ``operator`` is the
        RBAC record (env bootstrap admin or a stored operator account)
        or ``None`` when the request is an ephemeral share-link session.
        Read access is allowed to both; session inventory and
        mutations are operator-only (checked by the callers via the
        stashed ``self._portal_operator``).
        """
        if self._valid_ephemeral_cookie():
            return True, None
        ok, operator = self._resolve_operator()
        if ok and operator is not None:
            self._csrf_nonce()  # ensure the nonce cookie exists
        return ok, (operator if ok else None)

    def _resolve_operator(self):
        """Authenticate an operator: ``vnc_op`` session cookie first,
        then Basic credentials (which mint a fresh session).

        Returns ``(ok, operator)``. On success the session id is
        stashed on ``self._portal_sid`` — the CSRF token is bound to
        it, and logout/revocation targets it.
        """
        cookie_header = self.headers.get('Cookie', '')
        # A duplicated vnc_op name is ambiguous — cookie parsing order
        # is not portable, so duplicated session cookies never auth.
        if self._cookie_occurrences(cookie_header, 'vnc_op') == 1:
            rec = self._verify_op_cookie(
                cookie_value(cookie_header, 'vnc_op'))
            if rec is not None:
                sid, operator = rec
                self._portal_sid = sid
                return True, operator
        from vnc_remote_secure.security.http_auth import authenticate_landing
        ok, operator = authenticate_landing(
            self.headers.get('Authorization', ''),
            client_ip=client_ip_from(
                self.headers,
                self.peer_ip()))
        if ok and operator is not None:
            username = operator.get('username', 'admin')
            self._portal_sid = self._issue_op_session(username)
            # A fresh credential check is a fresh authentication —
            # step-up-sensitive API actions (passkey register/revoke)
            # measure recency from this mark.
            try:
                from vnc_remote_secure.security.step_up_auth import record_auth_time
                record_auth_time(username)
            except Exception:  # noqa: BLE001 - best-effort marker
                pass
        return ok, (operator if ok else None)

    def _issue_op_session(self, username: str) -> str:
        """Mint a signed operator-session cookie; returns the sid.

        Format: ``<sid>.<b64url username>.<exp>.<hmac>`` — the
        username is base64url-encoded so dots in usernames can never
        confuse the positional parser.
        """
        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac
        import secrets
        sid = secrets.token_urlsafe(16)
        exp = int(_time.time()) + self._OP_SESSION_TTL
        user64 = _b64.urlsafe_b64encode(
            username.encode('utf-8')).rstrip(b'=').decode('ascii')
        payload = f'{sid}.{user64}.{exp}'
        from vnc_remote_secure.security.authentication import _get_secret
        sig = _hmac.new(_get_secret(), f'op:{payload}'.encode(),
                        _hashlib.sha256).hexdigest()
        self._queue_cookie(
            f'vnc_op={payload}.{sig}; HttpOnly; Path=/; SameSite=Strict')
        self._index_op_session(username, sid, exp)
        # A fresh credential check mints the session — record it so
        # step-up-gated routes see this as a recent authentication.
        try:
            from vnc_remote_secure.security.step_up_auth import record_auth_time
            record_auth_time(username)
        except Exception:  # noqa: BLE001 - best-effort marker
            pass
        from vnc_remote_secure.security.audit import audit_event
        audit_event('operator_session_issued',
                    user=username, detail=f'sid={sid[:8]}…')
        return sid

    def _index_op_session(self, username: str, sid: str, exp: int):
        """Track live sids per operator; revoke the oldest past the cap."""
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            be = get_backend()
            ns = 'op_sessions'
            now = int(_time.time())
            active = []
            for k in be.list_keys(ns):
                try:
                    exp_i = int(be.get(ns, k) or 0)
                except (TypeError, ValueError):
                    be.delete(ns, k)
                    continue
                if exp_i <= now:
                    be.delete(ns, k)
                    continue
                user, _, ksid = k.partition('\x00')
                if user == username:
                    active.append((exp_i, ksid))
            while len(active) >= self._OP_SESSION_MAX_PER_USER:
                oldest_exp, oldest_sid = min(active)
                self._revoke_op_session(oldest_sid, oldest_exp)
                be.delete(ns, f'{username}\x00{oldest_sid}')
                active.remove((oldest_exp, oldest_sid))
            be.set_ttl(ns, f'{username}\x00{sid}', str(exp),
                       self._OP_SESSION_TTL)
        except Exception:  # noqa: BLE001 - indexing is best-effort
            pass

    @staticmethod
    def _cookie_occurrences(cookie_header: str, name: str) -> int:
        """Count ``name=`` appearances — a duplicated cookie name makes
        parsing order-dependent, so verifiers reject it outright."""
        return sum(
            1 for p in (cookie_header or '').split(';')
            if p.strip().startswith(name + '='))

    def _parse_op_cookie(self, value: str):
        """Structural parse of ``vnc_op`` — shape, charset, sizes,
        username decode, expiry window, signature. Returns
        ``(sid, username, exp)`` or None. No state consulted here."""
        import base64 as _b64
        import hashlib as _hashlib
        import hmac
        import re as _re
        if not value or len(value) > 256:
            return None
        if any(ord(c) < 0x21 or ord(c) == 0x7f for c in value):
            return None
        parts = value.split('.')
        if len(parts) != 4:
            return None
        sid, user64, exp_s, sig = parts
        if not _re.fullmatch(r'[A-Za-z0-9_-]{8,64}', sid):
            return None
        if not _re.fullmatch(r'[0-9]{1,12}', exp_s) \
                or not _re.fullmatch(r'[0-9a-f]{64}', sig):
            return None
        try:
            username = _b64.urlsafe_b64decode(
                user64 + '=' * (-len(user64) % 4)).decode('utf-8')
        except Exception:  # noqa: BLE001 - malformed b64
            return None
        if not username or len(username) > 64:
            return None
        now = _time.time()
        exp = int(exp_s)
        if exp <= now or exp > now + self._OP_SESSION_TTL + 60:
            return None
        from vnc_remote_secure.security.authentication import _get_secret
        expected = hmac.new(
            _get_secret(),
            f'op:{sid}.{user64}.{exp_s}'.encode(),
            _hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return sid, username, exp

    def _op_session_revoked(self, sid: str, username: str,
                            exp: int) -> bool:
        """Shared-state revocation: per-sid mark, or a per-user epoch
        that postdates this cookie's issue time (exp - TTL). Any
        backend error is a denial — fail closed."""
        try:
            from vnc_remote_secure.security.shared_state import get_backend
            backend = get_backend()
            if backend.get('op_revoked_sessions', sid):
                return True
            revoked_at = backend.get('op_revoked_users', username)
            if revoked_at and (exp - self._OP_SESSION_TTL) <= int(
                    float(revoked_at)):
                return True
            return False
        except Exception:  # noqa: BLE001 - fail closed
            return True

    def _resolve_op_identity(self, username: str):
        """Store user record, or the env bootstrap 'admin' — disabled
        accounts and unknown users resolve to None."""
        try:
            from vnc_remote_secure.security.operator_users import (
                get_permissions,
                load_store,
            )
            store = load_store()
            if username in store:
                if store[username].get('disabled'):
                    return None
                return {
                    'username': username,
                    'role': store[username].get('role', 'operator'),
                    'permissions': sorted(get_permissions(username)),
                }
        except Exception:  # noqa: BLE001
            return None
        if username == 'admin':
            return {'username': 'admin', 'role': 'admin',
                    'permissions': ['admin:*']}
        return None

    def _verify_op_cookie(self, value: str):
        """Verify a ``vnc_op`` cookie; returns ``(sid, operator)``.

        Format: ``<sid>.<b64user>.<exp>.<hmac>``. Stages: structural
        parse (``_parse_op_cookie``) → revocation marks
        (``_op_session_revoked``) → identity resolution
        (``_resolve_op_identity``).
        """
        parsed = self._parse_op_cookie(value)
        if parsed is None:
            return None
        sid, username, exp = parsed
        if self._op_session_revoked(sid, username, exp):
            return None
        operator = self._resolve_op_identity(username)
        if operator is None:
            return None
        return sid, operator

    def _queue_cookie(self, cookie: str) -> None:
        """Queue a Set-Cookie for this response (emitted by
        end_headers so every code path is covered once)."""
        self.__dict__.setdefault('_pending_cookies', []).append(cookie)

    def _revoke_op_session(self, sid: str, exp: int) -> None:
        """Mark an operator session id as revoked for its remaining TTL."""
        ttl = max(1, exp - int(_time.time()))
        from vnc_remote_secure.security.shared_state import get_backend
        get_backend().set_ttl('op_revoked_sessions', sid, '1', ttl)

    def _csrf_nonce(self) -> str:
        """Return this session's CSRF nonce, issuing a cookie if needed.

        The nonce lives in an HttpOnly cookie (``vnc_csrf``); the
        matching token — HMAC(secret, 'csrf:' + nonce) — is exposed to
        the SPA via the /api/v1/me payload, and mutations must present
        it as the X-CSRF-Token header.
        Revoking/rotating the cookie invalidates every token minted
        for it, and two sessions of the same user hold different
        tokens.
        """
        nonce = cookie_value(self.headers.get('Cookie', ''), 'vnc_csrf')
        if nonce and 16 <= len(nonce) <= 128 \
                and all(c.isalnum() or c in '-_' for c in nonce):
            return nonce
        # Reuse the nonce already minted for THIS response — calling
        # twice (e.g. /me emits the token, end_headers emits the
        # cookie) must agree on one value.
        pending = getattr(self, '_pending_csrf_nonce', None)
        if pending:
            return pending
        import secrets
        nonce = secrets.token_urlsafe(32)
        self._pending_csrf_nonce = nonce
        self._queue_cookie(
            f'vnc_csrf={nonce}; HttpOnly; Path=/; SameSite=Strict')
        return nonce

    def _csrf_token(self) -> str:
        """The token a mutation must present for this session —
        bound to BOTH the operator session id and the CSRF nonce, so a
        copied nonce cookie alone cannot mint a usable token."""
        from vnc_remote_secure.backend.api import _csrf_token
        return _csrf_token(getattr(self, '_portal_sid', ''),
                           self._csrf_nonce())

    def _check_csrf(self) -> bool:
        """Verify the CSRF token on a mutating request.

        The expected token is HMAC(secret, 'csrf:' + <vnc_csrf nonce>),
        presented via the X-CSRF-Token header. SameSite=Strict on the
        nonce cookie plus this token are two CSRF layers; Origin and
        Sec-Fetch-Site are checked separately in _operator_gate.
        """
        import hmac as _hmac

        from vnc_remote_secure.backend.api import _csrf_token
        nonce = cookie_value(self.headers.get('Cookie', ''), 'vnc_csrf')
        sid = getattr(self, '_portal_sid', '')
        if not nonce or not sid:
            return False
        presented = self.headers.get('X-CSRF-Token', '')
        if not presented:
            return False
        return _hmac.compare_digest(presented, _csrf_token(sid, nonce))

    def _flush_pending_cookies(self) -> None:
        """Emit queued cookies — called by the transport's
        ``end_headers`` implementation."""
        cookies = self.__dict__.pop('_pending_cookies', None) or []
        if cookies:
            trusted = env_flag('TRUSTED_PROXY', 'false')
            is_tls = ((trusted and
                       self.headers.get('X-Forwarded-Proto', '') == 'https')
                      or self.is_tls)
            for cookie in cookies:
                if is_tls and ' Secure' not in cookie:
                    cookie = cookie.replace('; HttpOnly', '; Secure; HttpOnly', 1)
                self.send_header('Set-Cookie', cookie)

    def _require_portal_auth(self) -> bool:
        """Ephemeral cookie or operator Basic-auth gate; sends 401."""
        authed, operator = self._portal_identity()
        if not authed:
            self.send_json_error('Unauthorized', 401, www_authenticate='Basic realm="VNC Portal"')
            return False
        self._portal_operator = operator
        return True

    # -----------------------------------------------------------------
    # Static SPA serving
    # -----------------------------------------------------------------
    _ADMIN_DIR = _ADMIN_DIR
    _ADMIN_TYPES = _ADMIN_TYPES

    def _serve_admin(self, path: str) -> None:
        """Serve the React admin SPA bundle — publicly reachable.

        Static assets live in ``web/static/admin`` (the Vite build
        output). Paths without a file extension fall back to
        index.html so client-side routing works on reload. The bundle
        carries no data: authentication is enforced by /api/v1/* —
        an unauthenticated visitor only sees the login page.
        """
        rel = (path[len('/admin'):] if path.startswith('/admin')
               else path).lstrip('/') or 'index.html'
        # SPA fallback: extensionless client routes serve index.html.
        if '.' not in os.path.basename(rel):
            rel = 'index.html'
        # Path traversal: resolve and require containment.
        full = os.path.normpath(os.path.join(self._ADMIN_DIR, rel))
        if not full.startswith(self._ADMIN_DIR + os.sep) and \
                full != self._ADMIN_DIR:
            self.send_json_error('Not found', 404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = self._ADMIN_TYPES.get(ext)
        if ctype is None or not os.path.isfile(full):
            self.send_json_error('Not found', 404)
            return
        try:
            with open(full, 'rb') as f:
                body = f.read()
        except OSError:
            self.send_json_error('Not found', 404)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        # HTML is the SPA shell — never cache it so a new deploy is
        # picked up; hashed assets may be cached safely. The CSP keeps
        # the old share page's posture: same-origin scripts only (the
        # bundle carries no inline JS), ws:/wss: connect for the
        # audio/gamepad/terminal clients, no frames, no foreign base.
        # 'unsafe-inline' in style-src is required by React style
        # attributes.
        if ext == '.html':
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header(
                'Content-Security-Policy',
                "default-src 'none'; "
                "script-src 'self'; connect-src 'self' ws: wss:; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; "
                "form-action 'self'; base-uri 'none'; "
                "frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _session_refresh_header(self):
        """Return a ``Set-Cookie`` value refreshing the session cookie.

        Re-issues ``vnc_session`` with an updated ``last_seen`` claim so
        SESSION_IDLE_TIMEOUT measures real inactivity. Returns ``None``
        when there is no session cookie or no refresh is due.
        """
        try:
            raw = cookie_value(
                self.headers.get('Cookie', ''), 'vnc_session')
            if not raw:
                return None
            from vnc_remote_secure.security.sessions import (
                refresh_session_cookie,
            )
            new_value = refresh_session_cookie(raw)
            if not new_value:
                return None
            # Same TLS detection as _handle_session_exchange: behind a
            # trusted proxy the backend socket is plain HTTP, so
            # X-Forwarded-Proto decides whether the refreshed cookie
            # keeps the Secure flag (a missing flag would downgrade
            # the attribute on re-issue).
            trusted = env_flag('TRUSTED_PROXY', 'false')
            is_tls = ((trusted and
                       self.headers.get('X-Forwarded-Proto', '') == 'https')
                      or self.is_tls)
            secure = ' Secure;' if is_tls else ''
            # SameSite=Strict matches the mint in
            # api_v1._queue_operator_service_cookie — a refresh must
            # never widen the operator cookie's scope.
            return (f'vnc_session={new_value};{secure} HttpOnly; Path=/; '
                    'SameSite=Strict')
        except Exception:  # noqa: BLE001 - refresh is best-effort
            return None

    # -----------------------------------------------------------------
    # Status payload
    # -----------------------------------------------------------------
    def _status_payload(self) -> dict:
        """Service-status payload shared by /status.json and
        /api/v1/status — delegated to the engine read model so the
        transport never touches service internals."""
        from vnc_remote_secure.engine.application import read_models
        return read_models.status(
            is_operator=getattr(self, '_portal_operator', None)
            is not None)

    def _serve_status_json(self):
        try:
            self.send_json(self._status_payload(), 200, indent=2)
        except Exception as e:
            log_exception(e, 'Landing _serve_status_json')
            self.send_json_error('Failed to build status JSON', 500)

    # -----------------------------------------------------------------
    # API dispatch
    # -----------------------------------------------------------------
    def _serve_api_get(self, path: str) -> None:
        """Dispatch a GET under /api/v1/ to the api_v1 module."""
        from urllib.parse import parse_qs, urlparse

        from vnc_remote_secure.backend.api import handle_get
        query = parse_qs(urlparse(self.path).query)
        try:
            if not handle_get(self, path, query):
                self.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001 - never take the portal down
            log_exception(e, 'api GET')
            self.send_json_error('Internal error', 500)

    def _serve_api_post(self, path: str) -> None:
        """Dispatch a POST under /api/v1/ to the api_v1 module."""
        from vnc_remote_secure.backend.api import handle_post
        try:
            if not handle_post(self, path):
                self.send_json_error('Not found', 404)
        except Exception as e:  # noqa: BLE001 - never take the portal down
            log_exception(e, 'api POST')
            self.send_json_error('Internal error', 500)

    def _operator_gate(self, permission):
        """Authenticate and authorize a mutating endpoint call.

        Runs operator auth (env bootstrap or operator store), the
        Origin check, and the per-role permission check. Returns the
        operator dict ``{'username', 'role', 'permissions'}`` on
        success; on failure it has already written the error response
        (401/403) and returns ``None``.
        """
        ok, operator = self._resolve_operator()
        if not ok:
            self.send_json_error('Operator credentials required', 401, www_authenticate='Basic realm="VNC Portal"')
            return None

        from vnc_remote_secure.security.auth_gateway import check_origin, get_allowed_origins
        origin = self.headers.get('Origin', '')
        if origin and not check_origin(origin, get_allowed_origins()):
            self.send_json_error('Invalid origin', 403)
            return None

        # Fetch Metadata CSRF defense-in-depth: browsers mark every
        # cross-site-initiated request with ``Sec-Fetch-Site:
        # cross-site`` — a forbidden header a malicious page cannot
        # strip or forge. It protects the case where Origin is absent
        # (some form posts, redirects). Non-browser clients (curl,
        # scripts) never send it, so automation is unaffected.
        if self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
            self.send_json_error('Cross-site request rejected', 403)
            return None

        # CSRF token bound to the vnc_csrf nonce cookie — required on
        # every /api/v1 mutation.
        if not self._check_csrf():
            self.send_json_error('CSRF token missing or invalid', 403)
            return None

        perms = set(operator.get('permissions') or [])
        if permission and permission not in perms \
                and 'admin:*' not in perms:
            from vnc_remote_secure.security.audit import audit_event
            audit_event('portal_permission_denied',
                      user=operator.get('username', '?'),
                      detail=f'required={permission}')
            self.send_json_error('Insufficient role for this action', 403)
            return None
        return operator


class AsgiPortalContext(PortalContext):
    """ASGI adapter: ``PortalContext`` over a Starlette ``Request``.

    Collects the response via the stdlib-shaped primitives
    (``send_response``/``send_header``/``end_headers``/``wfile``) so
    every ``api_v1`` handler works unchanged; ``to_response`` renders
    the result. ``_headers_buffer`` mirrors the stdlib buffer so
    ``send_security_headers``' emitted-header detection works too.
    """

    def __init__(self, headers, client_ip: str, is_tls: bool,
                 body: bytes = b'', path: str = '/', method: str = 'GET'):
        self.headers = headers
        self._client_ip = client_ip
        self.is_tls = is_tls
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.path = path
        self.command = method
        self._resp_status = 200
        self._resp_headers: list[tuple[str, str]] = []
        # Mimics BaseHTTPRequestHandler._headers_buffer: send_header
        # appends raw "Name: value" byte lines; http_headers inspects
        # it to skip duplicate security headers.
        self._headers_buffer: list[bytes] = []

    def send_response(self, status: int) -> None:
        self._resp_status = status

    def send_header(self, name: str, value: str) -> None:
        self._resp_headers.append((name, str(value)))
        self._headers_buffer.append(
            f'{name}: {value}\r\n'.encode('latin-1', 'replace'))

    def end_headers(self) -> None:
        # Security headers + queued cookies — the mixin emitted them
        # inside end_headers so every code path is covered once.
        from vnc_remote_secure.security.http_headers import send_security_headers
        send_security_headers(self, tls_enabled=self.is_tls)
        self._flush_pending_cookies()

    def to_response(self):
        """Render the collected response as a Starlette Response."""
        from starlette.responses import Response
        body = self.wfile.getvalue()
        resp = Response(content=body, status_code=self._resp_status)
        # Preserve the original header case — tests (and some clients)
        # read response headers case-sensitively via http.client.
        resp.raw_headers = [
            (n.encode('latin-1'), v.encode('latin-1'))
            for n, v in self._resp_headers]
        return resp
