"""Unit tests for backend.handlers.sessions — share-link CRUD wire
contracts with the engine use cases mocked."""

import io
import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import sessions as sess_h
from vnc_remote_secure.engine.domain import decision


class _Handler:
    def __init__(self, body=b"", headers=None):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.sent = []
        self.errors = []
        self._api_operator = {"username": "admin", "permissions": ["admin:*"]}
        self._api_params = {}

    def send_json(self, payload, status=200):
        self.sent.append((status, payload))

    def send_json_error(self, message, status, code=None):
        self.errors.append((status, message, code))


def _json_handler(payload: dict) -> _Handler:
    body = json.dumps(payload).encode()
    return _Handler(body=body, headers={"Content-Length": str(len(body))})


SESS_MOD = "vnc_remote_secure.engine.application.sessions"


def _fake_session(**kw):
    s = mock.Mock()
    s.to_dict.return_value = {"token_id": "tid1", **kw}
    s.expires_at = kw.get("expires_at", 123.0)
    s.role = kw.get("role", "viewer")
    s.permissions = kw.get("permissions", {"view"})
    s.single_use = kw.get("single_use", False)
    s.view_only = kw.get("view_only", False)
    s.no_terminal = kw.get("no_terminal", False)
    s.max_uses = kw.get("max_uses", 1)
    s.resource = kw.get("resource", None)
    s.allowed_ip = kw.get("allowed_ip", None)
    s.label = kw.get("label", None)
    return s


class TestListSessions:
    def test_status_filter_invalid_is_400(self):
        h = _Handler()
        exc = decision.UseCaseError(decision.ERR_INVALID, "bad status")
        with mock.patch(f"{SESS_MOD}.list_share_links", side_effect=exc):
            sess_h._get_sessions(h, {"status": ["bogus"]})
        assert h.errors[0][0] == 400
        assert "status must be one of" in h.errors[0][1]

    def test_pagination_orders_newest_first(self):
        h = _Handler()
        sessions = [
            {"token_id": "old", "created_at": 100.0},
            {"token_id": "new", "created_at": 200.0},
        ]
        with mock.patch(f"{SESS_MOD}.list_share_links", return_value=sessions):
            sess_h._get_sessions(h, {"status": ["all"], "limit": ["10"]})
        ids = [s["token_id"] for s in h.sent[0][1]["data"]["sessions"]]
        assert ids == ["new", "old"]

    def test_cursor_pages_forward(self):
        h = _Handler()
        sessions = [{"token_id": f"t{i}", "created_at": float(1000 - i)} for i in range(5)]
        with mock.patch(f"{SESS_MOD}.list_share_links", return_value=sessions):
            sess_h._get_sessions(h, {"status": ["all"], "limit": ["2"]})
        page1 = h.sent[0][1]["data"]
        assert page1["has_more"] is True and page1["next_cursor"]
        # second page via cursor
        h2 = _Handler()
        with mock.patch(f"{SESS_MOD}.list_share_links", return_value=sessions):
            sess_h._get_sessions(
                h2, {"status": ["all"], "limit": ["2"], "cursor": [page1["next_cursor"]]}
            )
        page2_ids = [s["token_id"] for s in h2.sent[0][1]["data"]["sessions"]]
        assert "t0" not in page2_ids and "t1" not in page2_ids

    def test_malformed_cursor_degrades_to_first_page(self):
        h = _Handler()
        sessions = [{"token_id": "a", "created_at": 1.0}]
        with mock.patch(f"{SESS_MOD}.list_share_links", return_value=sessions):
            sess_h._get_sessions(h, {"status": ["all"], "cursor": ["garbage"]})
        assert h.sent[0][0] == 200


class TestSessionDetail:
    def test_unknown_is_404(self):
        h = _Handler()
        h._api_params = {"token_id": "ghost"}
        with mock.patch(f"{SESS_MOD}.get_share_link", return_value=None):
            sess_h._get_session_detail(h, {})
        assert h.errors[0][0] == 404

    def test_detail_includes_connections(self):
        h = _Handler()
        h._api_params = {"token_id": "tid1"}
        sess = {"token_id": "tid1", "role": "viewer", "permissions": ["view"]}
        with (
            mock.patch(f"{SESS_MOD}.get_share_link", return_value=sess),
            mock.patch(f"{SESS_MOD}.share_link_connections", return_value=[{"ip": "1.2.3.4"}]),
        ):
            sess_h._get_session_detail(h, {})
        data = h.sent[0][1]["data"]
        assert data["connections"] == [{"ip": "1.2.3.4"}]
        assert data["session"]["token_id"] == "tid1"


class TestSessionCreate:
    def test_bad_body_rejected(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        sess_h._post_session_create(h, {})
        assert h.errors[0][1] == "Invalid JSON"

    def test_create_returns_fragment_url(self):
        h = _json_handler({"role": "viewer", "ttl_seconds": 3600})
        sess = _fake_session()
        with (
            mock.patch(f"{SESS_MOD}.create_share_link", return_value=(sess, "SIGNED-TOKEN")),
            mock.patch(
                "vnc_remote_secure.core.share_url.share_base_url",
                return_value="https://pi.local",
            ),
        ):
            sess_h._post_session_create(h, {})
        assert h.sent[0][0] == 201
        url = h.sent[0][1]["data"]["url"]
        assert url == "https://pi.local/share#t=SIGNED-TOKEN"
        assert "#t=" in url  # fragment, never query

    def test_create_use_case_error_maps(self):
        h = _json_handler({"role": "viewer"})
        exc = decision.UseCaseError(decision.ERR_PERMISSION, "cannot delegate")
        with mock.patch(f"{SESS_MOD}.create_share_link", side_effect=exc):
            sess_h._post_session_create(h, {})
        assert h.errors[0][0] == 403

    def test_email_best_effort_does_not_break(self):
        h = _json_handler({"role": "viewer", "email_to": "a@b.c"})
        sess = _fake_session()
        with (
            mock.patch(f"{SESS_MOD}.create_share_link", return_value=(sess, "TOK")),
            mock.patch(
                "vnc_remote_secure.core.share_url.share_base_url",
                return_value="https://x",
            ),
            mock.patch(
                "vnc_remote_secure.monitoring.alerts.send_email_alert",
                side_effect=RuntimeError("smtp down"),
            ),
        ):
            sess_h._post_session_create(h, {})
        assert h.sent[0][0] == 201
        assert h.sent[0][1]["data"]["emailed"] is False


class TestSessionRevoke:
    def test_uniform_200_exists_or_not(self):
        """Anti-enumeration: unknown token_id must not 404."""
        h1, h2 = _Handler(), _Handler()
        body = json.dumps({"token_id": "x"}).encode()
        for h in (h1, h2):
            h.rfile = io.BytesIO(body)
            h.headers = {"Content-Length": str(len(body))}
        with mock.patch(f"{SESS_MOD}.revoke_share_link", return_value=True):
            sess_h._post_session_revoke(h1, {})
        with mock.patch(f"{SESS_MOD}.revoke_share_link", return_value=False):
            sess_h._post_session_revoke(h2, {})
        assert h1.sent[0][0] == h2.sent[0][0] == 200
        assert h1.sent[0][1]["data"]["revoked"] is True
        assert h2.sent[0][1]["data"]["revoked"] is False

    def test_empty_token_id_is_400(self):
        h = _json_handler({"token_id": "   "})
        sess_h._post_session_revoke(h, {})
        assert h.errors[0][0] == 400

    def test_revoke_all_counts_and_alerts(self):
        h = _Handler()
        with (
            mock.patch(f"{SESS_MOD}.revoke_all_share_links", return_value=3),
            mock.patch("vnc_remote_secure.monitoring.alerts.notify") as nt,
        ):
            sess_h._post_session_revoke_all(h, {})
        assert h.sent[0][1]["data"]["revoked"] == 3
        nt.assert_called_once()


class TestSessionLabel:
    def test_missing_label_key_is_400_not_silent_clear(self):
        """{'label': null} clears; omitting the key is malformed."""
        h = _json_handler({"other": "field"})
        # schema is extra=forbid so 'other' fails validation first —
        # use an empty object instead
        h = _json_handler({})
        sess_h._patch_session_label(h, {})
        assert h.errors[0][0] == 400

    def test_explicit_null_clears(self):
        h = _Handler()
        h._api_params = {"token_id": "tid1"}
        body = b'{"label": null}'
        h.rfile = io.BytesIO(body)
        h.headers = {"Content-Length": str(len(body))}
        with mock.patch(f"{SESS_MOD}.update_share_link_label", return_value=True):
            sess_h._patch_session_label(h, {})
        assert h.sent[0][0] == 200

    def test_unknown_session_is_404(self):
        h = _Handler()
        h._api_params = {"token_id": "ghost"}
        body = b'{"label": "x"}'
        h.rfile = io.BytesIO(body)
        h.headers = {"Content-Length": str(len(body))}
        with mock.patch(f"{SESS_MOD}.update_share_link_label", return_value=False):
            sess_h._patch_session_label(h, {})
        assert h.errors[0][0] == 404
