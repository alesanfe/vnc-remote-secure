"""Unit tests for backend.handlers.power + a contract slice of ops.py.

These handlers are thin transport: every test pins the wire contract
(status codes, body limits, error mapping, step-up propagation) with
the engine use case mocked.
"""

import io
import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import ops as ops_h
from vnc_remote_secure.backend.handlers import power as power_h
from vnc_remote_secure.engine.domain import decision


class _Handler:
    def __init__(self, body=b"", headers=None):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)
        self.sent = []
        self.errors = []
        self._api_operator = {"username": "admin"}
        self._api_params = {}

    def send_json(self, payload, status=200):
        self.sent.append((status, payload))

    def send_json_error(self, message, status, code=None):
        self.errors.append((status, message, code))


def _json_handler(payload: dict, length=None) -> _Handler:
    body = json.dumps(payload).encode()
    return _Handler(body=body, headers={"Content-Length": str(length or len(body))})


def _empty_handler() -> _Handler:
    return _Handler(body=b"", headers={"Content-Length": "0"})


OPS_MOD = "vnc_remote_secure.engine.application.ops"
POWER_MOD = "vnc_remote_secure.engine.application.power"


class TestPowerAction:
    def test_bad_body_rejected(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        power_h._post_power(h, {})
        assert h.errors[0][1] == "Invalid JSON"

    def test_success_delegates_with_actor(self):
        h = _json_handler({"action": "restart"})
        with mock.patch(f"{POWER_MOD}.host_power", return_value={"action": "restart"}) as hp:
            power_h._post_power(h, {})
        assert h.sent[0][0] == 200
        hp.assert_called_once()
        assert hp.call_args.args[1] == "admin"

    def test_use_case_error_maps_step_up(self):
        h = _json_handler({"action": "shutdown"})
        exc = decision.UseCaseError(decision.ERR_STEP_UP, "reauth")
        with mock.patch(f"{POWER_MOD}.host_power", side_effect=exc):
            power_h._post_power(h, {})
        assert h.errors[0][2] == "STEP_UP_REQUIRED"

    def test_bad_action_is_400(self):
        h = _json_handler({"action": "explode"})
        with mock.patch(f"{POWER_MOD}.host_power", side_effect=ValueError("bad action")):
            power_h._post_power(h, {})
        assert h.errors[0][0] == 400

    def test_unexpected_is_500(self):
        h = _json_handler({"action": "restart"})
        with mock.patch(f"{POWER_MOD}.host_power", side_effect=RuntimeError("x")):
            power_h._post_power(h, {})
        assert h.errors[0][0] == 500


class TestPowerWol:
    def test_invalid_port_rejected(self):
        h = _json_handler({"mac": "AA:BB:CC:DD:EE:FF", "port": "abc"})
        power_h._post_power_wol(h, {})
        assert h.errors == [(400, "invalid port", None)]

    def test_mac_invalid_is_400(self):
        h = _json_handler({"mac": "not-a-mac"})
        with mock.patch(f"{POWER_MOD}.wake_on_lan", side_effect=ValueError("bad mac")):
            power_h._post_power_wol(h, {})
        assert h.errors[0][0] == 400

    def test_success(self):
        h = _json_handler({"mac": "AA:BB:CC:DD:EE:FF", "broadcast": "192.168.1.255"})
        with mock.patch(f"{POWER_MOD}.wake_on_lan", return_value={"sent": True}) as wol:
            power_h._post_power_wol(h, {})
        assert h.sent[0][0] == 200
        # broadcast + port forwarded verbatim
        assert wol.call_args.args[1] == "192.168.1.255"
        assert wol.call_args.kwargs["actor"] == "admin"

    def test_bad_body(self):
        h = _Handler(body=b"{bad", headers={"Content-Length": "4"})
        power_h._post_power_wol(h, {})
        assert h.errors[0][1] == "Invalid JSON"


class TestOpsLifecycle:
    def test_typed_body_invalid_action(self):
        h = _json_handler({"action": "explode"})
        ops_h._post_lifecycle(h, {})
        assert h.errors[0][1] == "Invalid request body" or h.errors[0][0] == 400

    def test_deferred_202(self):
        h = _json_handler({"action": "restart"})
        with mock.patch(f"{OPS_MOD}.lifecycle_action", return_value={"job_id": "j1"}) as la:
            ops_h._post_lifecycle(h, {})
        assert h.sent[0][0] == 202
        la.assert_called_once()

    def test_step_up_propagates_code(self):
        h = _json_handler({"action": "stop"})
        exc = decision.UseCaseError(decision.ERR_STEP_UP, "reauth")
        with mock.patch(f"{OPS_MOD}.lifecycle_action", side_effect=exc):
            ops_h._post_lifecycle(h, {})
        assert h.errors[0][2] == "STEP_UP_REQUIRED"


class TestOpsBackups:
    def test_list_skips_vanished_files(self):
        h = _empty_handler()
        with (
            mock.patch(
                "vnc_remote_secure.engine.infrastructure.stores.config_effective_profile"
            ) as _unused,
            mock.patch(
                "vnc_remote_secure.engine.application.read_models.backup_paths",
                return_value=["/nonexistent/a.tar.zst", "/nonexistent/b.tar.gz"],
            ),
        ):
            ops_h._get_backups(h, {})
        assert h.sent[0][0] == 200
        assert h.sent[0][1]["data"]["backups"] == []

    def test_verify_maps_domain_error(self):
        h = _json_handler({"file": "b.tar.zst"})
        exc = decision.UseCaseError(decision.ERR_NOT_FOUND, "no such backup")
        with mock.patch(f"{OPS_MOD}.verify_backup", side_effect=exc):
            ops_h._post_backup_verify(h, {})
        assert h.errors[0][0] == 404

    def test_restore_returns_202(self):
        h = _json_handler({"file": "b.tar.zst"})
        with mock.patch(f"{OPS_MOD}.restore_backup", return_value={"job_id": "j2"}) as rb:
            ops_h._post_backup_restore(h, {})
        assert h.sent[0][0] == 202
        assert rb.call_args.args[2]["transport"] == "api"


class TestOpsSecrets:
    def test_status_never_leaks(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.secrets_status", return_value={"secrets": []}):
            ops_h._get_secrets(h, {})
        assert h.sent[0][1]["data"] == {"secrets": []}

    def test_redact_uses_path_param(self):
        h = _empty_handler()
        h._api_params = {"name": "vnc_password"}
        with mock.patch(f"{OPS_MOD}.secret_redact", return_value={"redacted": True}):
            ops_h._get_secret_redact(h, {})
        assert h.sent[0][0] == 200

    def test_check_empty_body_defaults_fix_false(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.secrets_check", return_value={"findings": []}) as sc:
            ops_h._post_secrets_check(h, {})
        assert sc.call_args.kwargs["fix"] is False or sc.call_args.args[1] is False

    def test_check_with_body_reads_fix(self):
        h = _json_handler({"fix": True})
        with mock.patch(f"{OPS_MOD}.secrets_check", return_value={"findings": []}) as sc:
            ops_h._post_secrets_check(h, {})
        kwargs = sc.call_args.kwargs
        assert kwargs.get("fix") is True or sc.call_args.args[1] is True


class TestOpsConfig:
    def test_effective_profile_passthrough(self):
        h = _empty_handler()
        query = {"profile": ["hardened"]}
        with mock.patch(
            "vnc_remote_secure.engine.infrastructure.stores.config_effective_profile",
            return_value=[{"name": "X", "value": "v", "source": "env"}],
        ) as ce:
            ops_h._get_config_effective(h, query)
        ce.assert_called_once_with("hardened")
        assert h.sent[0][1]["data"]["profile"] == "hardened"

    def test_migrate_empty_body_applies(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.config_migrate", return_value={"migrated": []}) as cm:
            ops_h._post_config_migrate(h, {})
        assert cm.call_args.kwargs["dry_run"] is False

    def test_migrate_dry_run_body(self):
        h = _json_handler({"dry_run": True})
        with mock.patch(f"{OPS_MOD}.config_migrate", return_value={"migrated": []}) as cm:
            ops_h._post_config_migrate(h, {})
        assert cm.call_args.kwargs["dry_run"] is True


class TestOpsUpgrade:
    def test_status_delegates(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.upgrade_status", return_value={"current": "1.0"}):
            ops_h._get_upgrade(h, {})
        assert h.sent[0][0] == 200

    def test_run_empty_body_202(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.upgrade_run", return_value={"job_id": "j3"}) as ur:
            ops_h._post_upgrade(h, {})
        assert h.sent[0][0] == 202
        assert ur.call_args.kwargs["source"] is None

    def test_rollback_202(self):
        h = _empty_handler()
        with mock.patch(f"{OPS_MOD}.upgrade_rollback", return_value={"job_id": "j4"}):
            ops_h._post_upgrade_rollback(h, {})
        assert h.sent[0][0] == 202
