"""Unit tests for backend.handlers.common — the shared envelope,
body-reader, identity and gate plumbing every handler uses."""

import io
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import common as c


class _Handler:
    """Duck-typed handler: headers + rfile + response capture."""

    def __init__(self, body=b"", headers=None):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.sent = []
        self.errors = []

    def send_json(self, payload, status=200):
        self.sent.append((status, payload))

    def send_json_error(self, message, status, code=None):
        self.errors.append((status, message, code))


class TestEnvelope:
    def test_ok_envelope_shape(self):
        h = _Handler()
        c._ok(h, {"x": 1})
        status, payload = h.sent[0]
        assert status == 200
        assert payload["data"] == {"x": 1} and payload["error"] is None
        assert payload["request_id"]

    def test_err_delegates(self):
        h = _Handler()
        c._err(h, "nope", 403)
        assert h.errors == [(403, "nope", None)]

    def test_uc_err_step_up_carries_code(self):
        from vnc_remote_secure.engine.domain import decision

        h = _Handler()
        exc = decision.UseCaseError(decision.ERR_STEP_UP, "reauth")
        c._uc_err(h, exc)
        assert h.errors[0][2] == "STEP_UP_REQUIRED"

    def test_uc_err_maps_status(self):
        from vnc_remote_secure.engine.domain import decision

        h = _Handler()
        c._uc_err(h, decision.UseCaseError(decision.ERR_NOT_FOUND, "gone"))
        assert h.errors[0][0] == 404
        c._uc_err(_Handler(), decision.UseCaseError("SOMETHING_ELSE", "bad"))

    def test_uc_error_status_all_codes(self):
        from vnc_remote_secure.engine.domain import decision as d

        assert c._uc_error_status(d.UseCaseError(d.ERR_NOT_FOUND)) == 404
        assert c._uc_error_status(d.UseCaseError(d.ERR_PERMISSION)) == 403
        assert c._uc_error_status(d.UseCaseError(d.ERR_CONFLICT)) == 409
        assert c._uc_error_status(d.UseCaseError(d.ERR_LAST_ADMIN)) == 409
        assert c._uc_error_status(d.UseCaseError("UNKNOWN")) == 400


class TestAuthCtxAndOperator:
    def test_auth_ctx_binds_sid(self):
        h = _Handler(headers={"Cookie": "vnc_op=sid123; other=x"})
        h._api_operator = {"username": "admin"}
        ctx = c._auth_ctx(h)
        assert ctx == {"transport": "api", "username": "admin", "sid": "sid123"}

    def test_operator_missing_403(self):
        h = _Handler()
        assert c._operator(h) is None
        assert h.errors[0][0] == 403

    def test_operator_permission_admin_star(self):
        h = _Handler()
        h._portal_operator = {"username": "root", "permissions": ["admin:*"]}
        assert c._operator(h, "secrets:rotate") is not None

    def test_operator_permission_denied_audits(self):
        h = _Handler()
        h._portal_operator = {"username": "viewer", "permissions": ["sessions:view"]}
        with mock.patch("vnc_remote_secure.security.audit.audit_event") as ae:
            assert c._operator(h, "secrets:rotate") is None
        assert h.errors[0][0] == 403
        ae.assert_called_once()
        assert ae.call_args.args[0] == "api_permission_denied"


class TestReadJsonBody:
    def test_valid_object(self):
        h = _Handler(body=b'{"a": 1}', headers={"Content-Length": "8"})
        payload, err = c._read_json_body(h)
        assert payload == {"a": 1} and err is None

    def test_missing_length_rejected(self):
        h = _Handler(body=b"{}", headers={})
        payload, err = c._read_json_body(h)
        assert payload is None and err[1] == 400

    def test_oversized_rejected(self):
        h = _Handler(body=b"x" * 20000, headers={"Content-Length": "20000"})
        _, err = c._read_json_body(h)
        assert err[1] == 400

    def test_invalid_json(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        _, err = c._read_json_body(h)
        assert err == ("Invalid JSON", 400)

    def test_non_dict_rejected(self):
        h = _Handler(body=b"[1,2]", headers={"Content-Length": "5"})
        _, err = c._read_json_body(h)
        assert err == ("JSON object expected", 400)

    def test_bad_content_length_header(self):
        h = _Handler(body=b"{}", headers={"Content-Length": "abc"})
        _, err = c._read_json_body(h)
        assert err[1] == 400


class TestReadTypedBody:
    def test_valid_model(self):
        from pydantic import BaseModel

        class M(BaseModel):
            x: int

        h = _Handler(body=b'{"x": 5}', headers={"Content-Length": "8"})
        m, err = c._read_typed_body(h, M)
        assert m.x == 5 and err is None

    def test_extra_fields_named(self):
        from pydantic import BaseModel, ConfigDict

        class M(BaseModel):
            model_config = ConfigDict(extra="forbid")
            x: int

        h = _Handler(body=b'{"x": 1, "evil": 2}', headers={"Content-Length": "22"})
        _, err = c._read_typed_body(h, M)
        assert "evil" in err[0]

    def test_field_error_returns_detail(self):
        from pydantic import BaseModel

        class M(BaseModel):
            x: int

        h = _Handler(body=b'{"x": "nope"}', headers={"Content-Length": "13"})
        _, err = c._read_typed_body(h, M)
        assert err[1] == 400 and "x" in err[0]


class TestSerializers:
    def test_session_to_api_whitelist(self):
        s = {"token_id": "t1", "role": "viewer", "secret_field": "LEAK", "permissions": ["a"]}
        out = c.session_to_api(s)
        assert "secret_field" not in out and out["token_id"] == "t1"

    def test_operator_to_api_whitelist(self):
        out = c.operator_to_api({"username": "u", "role": "admin", "hash": "SECRET"})
        assert "hash" not in out

    def test_backup_to_api_encrypted_detection(self):
        class St:
            st_size = 10
            st_mtime = 1.5

        assert c.backup_to_api("/x/b.enc.tar.zst", St())["encrypted"] is True
        assert c.backup_to_api("/x/b.tar.zst", St())["encrypted"] is False

    def test_audit_event_to_api(self):
        out = c.audit_event_to_api({"seq": 1, "event": "e", "extra": "drop"})
        assert "extra" not in out and out["seq"] == 1

    def test_config_entry_to_api(self):
        out = c.config_entry_to_api({"name": "n", "value": "v", "source": "env", "raw": "x"})
        assert "raw" not in out


class TestExternalBase:
    def _h(self, headers):
        return _Handler(headers=headers)

    def test_trust_disabled_returns_none(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY", "false")
        assert c._external_base(self._h({"X-Forwarded-Host": "ok.com"})) is None

    def test_valid_forwarded(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY", "true")
        h = self._h({"X-Forwarded-Host": "portal.example.com", "X-Forwarded-Proto": "https"})
        assert c._external_base(h) == "https://portal.example.com"

    def test_evil_host_rejected(self, monkeypatch):
        """A crafted X-Forwarded-Host must not become reflected markup."""
        monkeypatch.setenv("TRUSTED_PROXY", "true")
        h = self._h({"X-Forwarded-Host": "<script>alert(1)</script>", "X-Forwarded-Proto": "https"})
        assert c._external_base(h) is None

    def test_bad_proto_rejected(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY", "true")
        h = self._h({"X-Forwarded-Host": "ok.com", "X-Forwarded-Proto": "javascript"})
        assert c._external_base(h) is None

    def test_first_value_of_chained_headers(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY", "true")
        h = self._h({"X-Forwarded-Host": "a.com, b.com", "X-Forwarded-Proto": "https, http"})
        assert c._external_base(h) == "https://a.com"


class TestProtocol:
    def test_ssl_context_gives_https(self, monkeypatch):
        import vnc_remote_secure.core.config as cfg
        import vnc_remote_secure.security.certificates as certs

        monkeypatch.setattr(cfg, "get_config", lambda: {"ssl_cert": "c", "ssl_key": "k"})
        monkeypatch.setattr(certs, "create_ssl_context", lambda *a: object())
        assert c._protocol() == "https"

    def test_no_context_gives_http(self, monkeypatch):
        import vnc_remote_secure.core.config as cfg
        import vnc_remote_secure.security.certificates as certs

        monkeypatch.setattr(cfg, "get_config", lambda: {"ssl_cert": "", "ssl_key": ""})
        monkeypatch.setattr(certs, "create_ssl_context", lambda *a: None)
        assert c._protocol() == "http"

    def test_config_failure_falls_back_http(self, monkeypatch):
        import vnc_remote_secure.core.config as cfg

        monkeypatch.setattr(cfg, "get_config", lambda: (_ for _ in ()).throw(RuntimeError("x")))
        assert c._protocol() == "http"


class TestEphemeralSession:
    def test_not_ephemeral_returns_none(self):
        h = _Handler()
        h._api_ephemeral = False
        assert c._ephemeral_session(h) is None

    def test_missing_cookie_returns_none(self):
        h = _Handler(headers={"Cookie": ""})
        h._api_ephemeral = True
        assert c._ephemeral_session(h) is None

    def test_store_lookup(self, monkeypatch):
        h = _Handler(headers={"Cookie": "vnc_ephemeral=tok1"})
        h._api_ephemeral = True
        fake = mock.Mock()
        fake.get = lambda t: {"token_id": "t1"} if t == "tok1" else None
        import vnc_remote_secure.engine.infrastructure.stores as stores

        monkeypatch.setattr(stores, "session_store", lambda: fake)
        monkeypatch.setattr(stores, "session_refresh", lambda s: None)
        out = c._ephemeral_session(h)
        assert out == {"token_id": "t1"}


class TestActorName:
    def test_operator_wins(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        assert c._actor_name(h) == "admin"

    def test_anonymous(self):
        h = _Handler()
        h._api_ephemeral = False
        assert c._actor_name(h) == "anonymous"

    def test_guest_fingerprint(self, monkeypatch):
        h = _Handler(headers={"Cookie": "vnc_ephemeral=tok"})
        h._api_ephemeral = True
        fake = mock.Mock()
        fake.get = lambda t: mock.Mock(to_dict=lambda: {"token_id": "tid-9"})
        import vnc_remote_secure.engine.infrastructure.stores as stores

        monkeypatch.setattr(stores, "session_store", lambda: fake)
        monkeypatch.setattr(stores, "session_refresh", lambda s: None)
        assert c._actor_name(h) == "guest:tid-9"


class TestCsrfToken:
    def test_deterministic_and_bound(self):
        t1 = c._csrf_token("sid1", "nonce1")
        t2 = c._csrf_token("sid1", "nonce1")
        t3 = c._csrf_token("sid2", "nonce1")
        assert t1 == t2 and t1 != t3
        assert len(t1) == 64  # sha256 hex

    def test_nonce_binding(self):
        assert c._csrf_token("sid", "n1") != c._csrf_token("sid", "n2")


class TestPublicGate:
    def test_clean_request_passes(self):
        assert c._public_gate(_Handler(headers={})) is True

    def test_bad_origin_rejected(self, monkeypatch):
        import vnc_remote_secure.security.auth_gateway as gw

        monkeypatch.setattr(gw, "get_allowed_origins", lambda: ["https://ok"])
        monkeypatch.setattr(gw, "check_origin", lambda o, a, s=None: False)
        h = _Handler(headers={"Origin": "https://evil"})
        assert c._public_gate(h) is False
        assert h.errors[0][0] == 403

    def test_cross_site_fetch_rejected(self):
        h = _Handler(headers={"Sec-Fetch-Site": "cross-site"})
        assert c._public_gate(h) is False

    def test_same_site_fetch_passes(self):
        h = _Handler(headers={"Sec-Fetch-Site": "same-origin"})
        assert c._public_gate(h) is True
