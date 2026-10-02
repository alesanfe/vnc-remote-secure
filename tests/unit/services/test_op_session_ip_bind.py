"""OP_SESSION_IP_BIND — MeshCentral-style token binding for vnc_op.

When enabled, the issuing client IP is folded into the cookie's HMAC:
the same cookie value verifies from the origin address and fails from
any other — a stolen cookie is not portable.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.context import PortalContext  # noqa: E402


class _Ctx(PortalContext):
    """Minimal context: the issue/verify paths only need headers +
    peer_ip() — cookie emission goes to _pending_cookies."""

    def __init__(self, ip: str, headers=None):
        self._client_ip = ip
        self.headers = headers or {}

    def send_response(self, status):  # pragma: no cover - unused
        pass

    def send_header(self, name, value):  # pragma: no cover - unused
        pass

    def end_headers(self):  # pragma: no cover - unused
        pass


def _op_cookie_value(ctx: PortalContext) -> str:
    cookie = next(c for c in ctx.__dict__["_pending_cookies"] if c.startswith("vnc_op="))
    return cookie.split(";", 1)[0].split("=", 1)[1]


def test_ip_bind_rejects_cookie_from_other_ip(monkeypatch):
    monkeypatch.setenv("OP_SESSION_IP_BIND", "true")
    issuer = _Ctx("10.1.1.1")
    issuer._issue_op_session("admin")
    value = _op_cookie_value(issuer)

    assert _Ctx("10.1.1.1")._verify_op_cookie(value) is not None
    assert _Ctx("10.1.1.2")._verify_op_cookie(value) is None


def test_ip_bind_off_keeps_cookie_portable(monkeypatch):
    monkeypatch.delenv("OP_SESSION_IP_BIND", raising=False)
    issuer = _Ctx("10.1.1.1")
    issuer._issue_op_session("admin")
    value = _op_cookie_value(issuer)

    # Default behaviour unchanged: no IP folding in the signature.
    assert _Ctx("10.9.9.9")._verify_op_cookie(value) is not None


def test_ip_bind_on_rejects_unbound_cookie(monkeypatch):
    """A cookie minted with binding OFF must not verify once the flag
    flips on — the signature shape itself is bound."""
    monkeypatch.delenv("OP_SESSION_IP_BIND", raising=False)
    issuer = _Ctx("10.1.1.1")
    issuer._issue_op_session("admin")
    value = _op_cookie_value(issuer)

    monkeypatch.setenv("OP_SESSION_IP_BIND", "true")
    assert _Ctx("10.1.1.1")._verify_op_cookie(value) is None
