"""Unit tests for backend.handlers.controls + monitoring + files —
thin transport contract tests with engine/stores mocked."""

import io
import json
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import controls as ctl_h
from vnc_remote_secure.backend.handlers import files as files_h
from vnc_remote_secure.backend.handlers import monitoring as mon_h
from vnc_remote_secure.engine.domain import decision


class _Handler:
    def __init__(self, body=b"", headers=None):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.sent = []
        self.errors = []
        self._api_operator = {"username": "admin", "permissions": ["admin:*"]}
        self._api_ephemeral = False
        self._api_params = {}

    def send_json(self, payload, status=200):
        self.sent.append((status, payload))

    def send_json_error(self, message, status, code=None):
        self.errors.append((status, message, code))

    def send_response(self, code):
        pass

    def send_header(self, k, v):
        pass

    def end_headers(self):
        pass


def _json_handler(payload: dict) -> _Handler:
    body = json.dumps(payload).encode()
    return _Handler(body=body, headers={"Content-Length": str(len(body))})


class TestMaintenance:
    def test_get_status(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.application.maintenance.maintenance_status",
            return_value={"active": False},
        ):
            ctl_h._get_maintenance(h, {})
        assert h.sent[0][1]["data"] == {"active": False}

    def test_post_toggles_with_actor(self):
        h = _json_handler({"active": True, "reason": "upgrade"})
        with mock.patch(
            "vnc_remote_secure.engine.application.maintenance.set_maintenance",
            return_value={"active": True},
        ) as sm:
            ctl_h._post_maintenance(h, {})
        assert h.sent[0][0] == 200
        assert sm.call_args.args[0] == "admin"
        assert sm.call_args.args[1] is True
        assert sm.call_args.kwargs["reason"] == "upgrade"

    def test_post_use_case_error_maps(self):
        h = _json_handler({"active": True})
        exc = decision.UseCaseError(decision.ERR_STEP_UP, "reauth")
        with mock.patch(
            "vnc_remote_secure.engine.application.maintenance.set_maintenance",
            side_effect=exc,
        ):
            ctl_h._post_maintenance(h, {})
        assert h.errors[0][0] == 403

    def test_post_bad_body(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        ctl_h._post_maintenance(h, {})
        assert h.errors[0][1] == "Invalid JSON"


class TestGamepadControl:
    def test_stop_sets_flag_and_audits(self):
        h = _Handler()
        with (
            mock.patch("vnc_remote_secure.engine.infrastructure.stores.gamepad_set_stopped") as gs,
            mock.patch("vnc_remote_secure.security.audit.audit_event") as ae,
        ):
            ctl_h._post_gamepad_stop(h, {})
        gs.assert_called_once_with(True)
        ae.assert_called_once()
        assert h.sent[0][1]["data"] == {"gamepad_stopped": True}

    def test_resume(self):
        h = _Handler()
        with mock.patch("vnc_remote_secure.engine.infrastructure.stores.gamepad_set_stopped") as gs:
            ctl_h._post_gamepad_resume(h, {})
        gs.assert_called_once_with(False)

    def test_store_failure_is_500(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.infrastructure.stores.gamepad_set_stopped",
            side_effect=RuntimeError("backend down"),
        ):
            ctl_h._post_gamepad_stop(h, {})
        assert h.errors[0][0] == 500


class TestMonitoringReadModels:
    @pytest.mark.parametrize(
        "fn,mod_attr",
        [
            ("_get_health", "health"),
            ("_get_posture", "posture"),
            ("_get_security_overview", "security_overview"),
            ("_get_doctor", "doctor"),
            ("_get_audit_verify", "audit_integrity"),
        ],
    )
    def test_read_model_delegates(self, fn, mod_attr):
        h = _Handler()
        with mock.patch(
            f"vnc_remote_secure.engine.application.read_models.{mod_attr}",
            return_value={"ok": True},
        ):
            getattr(mon_h, fn)(h, {})
        assert h.sent[0][1]["data"] == {"ok": True}

    def test_read_model_failure_is_500(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.health",
            side_effect=RuntimeError("x"),
        ):
            mon_h._get_health(h, {})
        assert h.errors[0][0] == 500


class TestAuditPagination:
    def test_limit_clamped_to_500(self):
        h = _Handler()
        query = {"limit": ["999999"]}
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.audit_page",
            return_value={"entries": [], "next_cursor": None, "has_more": False},
        ) as ap:
            mon_h._get_audit(h, query)
        assert ap.call_args.args[0] == 500

    def test_invalid_cursor_is_400(self):
        h = _Handler()
        mon_h._get_audit(h, {"cursor": ["not-an-int"]})
        assert h.errors[0] == (400, "Invalid cursor", None)

    def test_filters_length_capped(self):
        h = _Handler()
        long_user = "u" * 500
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.audit_page",
            return_value={"entries": [], "next_cursor": None, "has_more": False},
        ) as ap:
            mon_h._get_audit(h, {"user": [long_user]})
        assert len(ap.call_args.kwargs["user"]) == 128

    def test_entries_serialized_whitelist(self):
        h = _Handler()
        entry = {"seq": 1, "event": "e", "user": "u", "secret": "DROP"}
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.audit_page",
            return_value={"entries": [entry], "next_cursor": None, "has_more": False},
        ):
            mon_h._get_audit(h, {})
        out = h.sent[0][1]["data"]["entries"][0]
        assert "secret" not in out and out["event"] == "e"


class TestJobs:
    def test_jobs_delegates_limit(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.jobs",
            return_value=[{"id": "j1"}],
        ) as jb:
            mon_h._get_jobs(h, {"limit": ["10"]})
        assert jb.call_args.args[0] == 10

    def test_job_detail_use_case_error(self):
        h = _Handler()
        h._api_params = {"jid": "missing"}
        exc = decision.UseCaseError(decision.ERR_NOT_FOUND, "no job")
        with mock.patch("vnc_remote_secure.engine.application.ops.job_status", side_effect=exc):
            mon_h._get_job_detail(h, {})
        assert h.errors[0][0] == 404


class TestFilesHandlers:
    def _ephemeral_handler(self):
        """Handler that looks like an activated share-link guest."""
        h = _Handler()
        h._api_operator = None
        sess = mock.Mock()
        sess.resource = "files"
        sess.has_permission.return_value = True
        h._ephemeral_session = sess  # not used; patched below
        return h, sess

    def test_operator_gets_file_list(self):
        h = _Handler()
        with (
            mock.patch(
                "vnc_remote_secure.engine.application.files.list_dir",
                return_value={"path": "", "entries": []},
            ) as ld,
            mock.patch(
                "vnc_remote_secure.engine.application.files.share_info",
                return_value={"max_file_bytes": 1},
            ),
        ):
            files_h._get_files(h, {})
        assert h.sent[0][0] == 200
        ld.assert_called_once()

    def test_guest_without_file_transfer_denied(self):
        h, sess = self._ephemeral_handler()
        sess.has_permission.return_value = False
        with mock.patch(
            "vnc_remote_secure.backend.handlers.files._ephemeral_session",
            return_value=sess,
        ):
            files_h._get_files(h, {})
        assert h.errors[0][0] == 403

    def test_guest_wrong_resource_denied(self):
        h, sess = self._ephemeral_handler()
        sess.resource = "desktop"
        with mock.patch(
            "vnc_remote_secure.backend.handlers.files._ephemeral_session",
            return_value=sess,
        ):
            files_h._get_files(h, {})
        assert h.errors[0] == (404, "Not found", None)

    def test_guest_unbound_resource_allowed_with_perm(self):
        h, sess = self._ephemeral_handler()
        sess.resource = None
        sess.has_permission.return_value = True
        with (
            mock.patch(
                "vnc_remote_secure.backend.handlers.files._ephemeral_session",
                return_value=sess,
            ),
            mock.patch(
                "vnc_remote_secure.engine.application.files.list_dir",
                return_value={"path": "", "entries": []},
            ),
            mock.patch(
                "vnc_remote_secure.engine.application.files.share_info",
                return_value={},
            ),
        ):
            files_h._get_files(h, {})
        assert h.sent[0][0] == 200
        # permission checked against the files resource
        sess.has_permission.assert_called_with("file_transfer", resource="files")

    def test_download_sends_attachment(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.application.files.read_file",
            return_value=(b"data", "report.pdf"),
        ):
            files_h._get_files_download(h, {"path": ["report.pdf"]})
        assert h.sent == []  # raw response, not JSON envelope
        assert h.wfile.getvalue() == b"data"

    def test_download_value_error_is_400(self):
        h = _Handler()
        with mock.patch(
            "vnc_remote_secure.engine.application.files.read_file",
            side_effect=ValueError("path escapes the share root"),
        ):
            files_h._get_files_download(h, {"path": ["../../etc/passwd"]})
        assert h.errors[0][0] == 400

    def test_upload_decodes_base64(self):
        import base64

        h = _json_handler({"path": "up.bin", "content_b64": base64.b64encode(b"hi").decode()})
        with mock.patch(
            "vnc_remote_secure.engine.application.files.write_file",
            return_value={"path": "up.bin"},
        ) as wf:
            files_h._post_files_upload(h, {})
        assert h.sent[0][0] == 201
        assert wf.call_args.args[1] == b"hi"

    def test_upload_bad_base64_is_400(self):
        h = _json_handler({"path": "x", "content_b64": "!!!not-b64!!!"})
        files_h._post_files_upload(h, {})
        assert h.errors[0] == (400, "content_b64 must be base64", None)

    def test_upload_exists_is_409(self):
        h = _json_handler({"path": "x", "content_b64": "aGk="})
        with mock.patch(
            "vnc_remote_secure.engine.application.files.write_file",
            side_effect=FileExistsError(),
        ):
            files_h._post_files_upload(h, {})
        assert h.errors[0][0] == 409

    def test_mkdir_delegates(self):
        h = _json_handler({"path": "newdir"})
        with mock.patch(
            "vnc_remote_secure.engine.application.files.mkdir",
            return_value={"path": "newdir"},
        ) as md:
            files_h._post_files_mkdir(h, {})
        assert h.sent[0][0] == 201
        md.assert_called_once()
