"""Unit tests for backend.handlers.chat + recordings — thin transport
contract tests with the engine use cases mocked."""

import io
import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import chat as chat_h
from vnc_remote_secure.backend.handlers import recordings as rec_h
from vnc_remote_secure.engine.domain import decision


class _Handler:
    def __init__(self, body=b"", headers=None, wfile=None):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.wfile = wfile if wfile is not None else io.BytesIO()
        self.sent = []
        self.errors = []
        self.responses = []
        self._api_operator = None
        self._api_ephemeral = False
        self._api_params = {}

    def send_json(self, payload, status=200):
        self.sent.append((status, payload))

    def send_json_error(self, message, status, code=None):
        self.errors.append((status, message, code))

    def send_response(self, code):
        self.responses.append(code)

    def send_header(self, k, v):
        pass

    def end_headers(self):
        pass


def _json_handler(payload: dict) -> _Handler:
    body = json.dumps(payload).encode()
    return _Handler(body=body, headers={"Content-Length": str(len(body))})


CHAT_MOD = "vnc_remote_secure.engine.application.chat"
REC_MOD = "vnc_remote_secure.engine.application.recordings"


class TestChatSessionId:
    def test_operator_uses_query_param(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        assert chat_h._chat_session_id(h, {"session": ["sess-1"]}) == "sess-1"

    def test_operator_post_body_param(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        assert chat_h._chat_session_id(h, {}, {"session": "sess-2"}) == "sess-2"

    def test_operator_no_session_is_none(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        assert chat_h._chat_session_id(h, {}) is None

    def test_guest_derives_from_grant_never_caller(self, monkeypatch):
        """A guest's channel id comes from their cookie session — a
        caller-supplied 'session' in the body is ignored."""
        h = _json_handler({"session": "VICTIM-SESSION", "text": "hi"})
        h._api_ephemeral = True
        h.headers["Cookie"] = "vnc_ephemeral=tok"
        fake_session = mock.Mock()
        fake_session.to_dict.return_value = {"token_id": "own-grant"}
        fake_store = mock.Mock()
        fake_store.get.return_value = fake_session
        import vnc_remote_secure.engine.infrastructure.stores as stores

        monkeypatch.setattr(stores, "session_store", lambda: fake_store)
        monkeypatch.setattr(stores, "session_refresh", lambda s: None)
        assert chat_h._chat_session_id(h, {}, {"session": "VICTIM"}) == "own-grant"

    def test_anonymous_gets_none(self):
        h = _Handler()
        h._api_ephemeral = False
        assert chat_h._chat_session_id(h, {}) is None


class TestChatEndpoints:
    def test_get_requires_session(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        chat_h._get_chat(h, {})
        assert h.errors[0] == (400, "session required", None)

    def test_get_lists_messages(self):
        h = _Handler()
        h._api_operator = {"username": "admin"}
        with mock.patch(f"{CHAT_MOD}.list_messages", return_value=[{"text": "hi"}]):
            chat_h._get_chat(h, {"session": ["s1"]})
        assert h.sent[0][1]["data"]["messages"] == [{"text": "hi"}]

    def test_post_creates_message(self):
        h = _json_handler({"session": "s1", "text": "hello"})
        h._api_operator = {"username": "admin"}
        with mock.patch(f"{CHAT_MOD}.post_message", return_value={"id": "m1"}):
            chat_h._post_chat(h, {})
        assert h.sent[0][0] == 201

    def test_post_bad_json(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        chat_h._post_chat(h, {})
        assert h.errors[0][1] == "Invalid JSON"

    def test_post_value_error_is_400(self):
        h = _json_handler({"session": "s1", "text": "x" * 100})
        h._api_operator = {"username": "admin"}
        with mock.patch(f"{CHAT_MOD}.post_message", side_effect=ValueError("too long")):
            chat_h._post_chat(h, {})
        assert h.errors[0][0] == 400


class TestRecordings:
    def test_screenshot_bytes(self):
        h = _Handler()
        with mock.patch(f"{REC_MOD}.screenshot", return_value=b"\x89PNG"):
            rec_h._get_screenshot(h, {})
        assert h.responses == [200]
        assert h.wfile.getvalue() == b"\x89PNG"

    def test_screenshot_failure_is_502(self):
        h = _Handler()
        with mock.patch(f"{REC_MOD}.screenshot", side_effect=RuntimeError("rfb down")):
            rec_h._get_screenshot(h, {})
        assert h.errors[0][0] == 502

    def test_list_recordings(self):
        h = _Handler()
        with mock.patch(f"{REC_MOD}.list_recordings", return_value=[{"id": "r1"}]):
            rec_h._get_recordings(h, {})
        assert h.sent[0][1]["data"]["recordings"] == [{"id": "r1"}]

    def test_start_recording_201(self):
        h = _Handler()
        with mock.patch(f"{REC_MOD}.start", return_value={"id": "r2"}):
            rec_h._post_recordings(h, {})
        assert h.sent[0][0] == 201

    def test_get_recording_404(self):
        h = _Handler()
        h._api_params = {"id": "missing"}
        with mock.patch(f"{REC_MOD}.read", side_effect=FileNotFoundError()):
            rec_h._get_recording(h, {})
        assert h.errors[0][0] == 404

    def test_get_recording_sends_bytes(self):
        h = _Handler()
        h._api_params = {"id": "r1"}
        with mock.patch(f"{REC_MOD}.read", return_value=(b"blob", "evil;name.png")):
            rec_h._get_recording(h, {})
        assert h.responses == [200]
        # filename sanitized: ';' stripped from Content-Disposition

    def test_stop_not_running_404(self):
        h = _Handler()
        h._api_params = {"id": "gone"}
        with mock.patch(f"{REC_MOD}.stop", side_effect=FileNotFoundError()):
            rec_h._post_recording_stop(h, {})
        assert h.errors[0][0] == 404

    def test_delete_step_up_code_propagates(self):
        h = _Handler()
        h._api_params = {"id": "r1"}
        exc = decision.UseCaseError(decision.ERR_STEP_UP, "reauth")
        with mock.patch(f"{REC_MOD}.delete", side_effect=exc):
            rec_h._delete_recording(h, {})
        assert h.errors[0][2] == "STEP_UP_REQUIRED"

    def test_delete_runtime_error_is_409(self):
        h = _Handler()
        h._api_params = {"id": "r1"}
        with mock.patch(f"{REC_MOD}.delete", side_effect=RuntimeError("still recording")):
            rec_h._delete_recording(h, {})
        assert h.errors[0][0] == 409

    def test_send_bytes_sanitizes_filename(self):
        """Content-Disposition filename must not carry header chars."""
        h = _Handler()
        headers = []

        def cap(k, v):
            headers.append((k, v))

        h.send_header = cap
        rec_h._send_bytes(h, b"x", "application/octet-stream", 'a"b;\r\nEvil: 1.png')
        dispo = [v for k, v in headers if k == "Content-Disposition"][0]
        assert (
            "\r" not in dispo
            and "\n" not in dispo
            and ";" not in dispo.split("filename=")[1].strip('"')
        )
