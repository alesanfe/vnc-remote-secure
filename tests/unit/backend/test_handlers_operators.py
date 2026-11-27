"""Unit tests for backend.handlers.operators — account + passkey
management wire contracts with use cases mocked."""

import io
import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.backend.handlers import operators as ops_h
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


OPS_APP = "vnc_remote_secure.engine.application.operators"
PASSKEYS = "vnc_remote_secure.engine.application.passkeys"
STORE = "vnc_remote_secure.security.operator_users"


class TestOperatorList:
    def test_index_serialized_whitelist(self):
        h = _Handler()
        users = [{"username": "a", "role": "admin", "hash": "SECRET", "disabled": False}]
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.operators_index",
            return_value=users,
        ):
            ops_h._get_operators(h, {})
        out = h.sent[0][1]["data"]["operators"][0]
        assert "hash" not in out and out["username"] == "a"

    def test_detail_404(self):
        h = _Handler()
        h._api_params = {"username": "ghost"}
        with mock.patch(
            "vnc_remote_secure.engine.application.read_models.operator_detail",
            return_value=None,
        ):
            ops_h._get_operator_detail(h, {})
        assert h.errors[0][0] == 404


class TestPatchOperator:
    def _patch(self, payload):
        h = _json_handler(payload)
        h._api_params = {"username": "alice"}
        return h

    def _store_has(self, username="alice"):
        return mock.patch(f"{STORE}.load_store", return_value={username: {"hash": "x"}})

    def test_empty_patch_is_400(self):
        h = self._patch({})
        ops_h._patch_operator(h, {})
        assert h.errors[0][0] == 400
        assert "Allowed fields" in h.errors[0][1]

    def test_unknown_operator_is_404(self):
        h = self._patch({"role": "viewer"})
        with mock.patch(f"{STORE}.load_store", return_value={}):
            ops_h._patch_operator(h, {})
        assert h.errors[0][0] == 404

    def test_role_update_delegates(self):
        h = self._patch({"role": "viewer"})
        with (
            self._store_has(),
            mock.patch(
                f"{OPS_APP}.update_operator",
                return_value={"record": {"role": "viewer"}, "changed": True, "sessions_revoked": 0},
            ) as upd,
        ):
            ops_h._patch_operator(h, {})
        assert h.sent[0][0] == 200
        assert upd.call_args.kwargs["role"] == "viewer"
        assert "password" not in upd.call_args.kwargs

    def test_weak_password_rejected_before_use_case(self):
        h = self._patch({"password": "changeme"})
        with self._store_has(), mock.patch(f"{OPS_APP}.update_operator") as upd:
            ops_h._patch_operator(h, {})
        assert h.errors[0][0] == 400
        upd.assert_not_called()

    def test_internal_fields_never_settable(self):
        """A payload naming hash/timestamps is extra=forbid → 400."""
        h = self._patch({"hash": "forged"})
        ops_h._patch_operator(h, {})
        assert h.errors[0][0] == 400


class TestCreateOperator:
    def test_weak_password_rejected(self):
        h = _json_handler({"username": "bob", "password": "12345678", "role": "viewer"})
        ops_h._post_operator_create(h, {})
        assert h.errors[0][0] == 400

    def test_create_delegates_with_actor_perms(self):
        h = _json_handler({"username": "bob", "password": "Str0ng!Passw0rd", "role": "viewer"})
        with mock.patch(
            f"{OPS_APP}.create_operator",
            return_value={"role": "viewer", "disabled": False},
        ) as co:
            ops_h._post_operator_create(h, {})
        assert h.sent[0][0] == 201
        assert co.call_args.args[0] == "admin"
        assert "admin:*" in co.call_args.args[1]

    def test_last_admin_error_maps_409(self):
        h = _json_handler({"username": "x", "password": "Str0ng!Passw0rd"})
        exc = decision.UseCaseError(decision.ERR_LAST_ADMIN, "last admin")
        with mock.patch(f"{OPS_APP}.create_operator", side_effect=exc):
            ops_h._post_operator_create(h, {})
        assert h.errors[0][0] == 409


class TestDeleteAndRestore:
    def test_delete_delegates(self):
        h = _Handler()
        h._api_params = {"username": "bob"}
        with mock.patch(f"{OPS_APP}.delete_operator") as dl:
            ops_h._delete_operator(h, {})
        assert h.sent[0][1]["data"] == {"deleted": True}
        dl.assert_called_once_with("admin", "bob")

    def test_restore_returns_disabled_record(self):
        h = _Handler()
        h._api_params = {"username": "bob"}
        with mock.patch(
            f"{OPS_APP}.restore_operator",
            return_value={"role": "viewer", "disabled": True},
        ):
            ops_h._post_operator_restore(h, {})
        assert h.sent[0][0] == 200
        assert h.sent[0][1]["data"]["operator"]["disabled"] is True

    def test_revoke_sessions_delegates(self):
        h = _Handler()
        h._api_params = {"username": "bob"}
        with mock.patch(f"{OPS_APP}.revoke_sessions") as rs:
            ops_h._post_operator_revoke_sessions(h, {})
        rs.assert_called_once_with("admin", "bob")


class TestPasskeys:
    def test_list_requires_existing_operator(self):
        h = _Handler()
        h._api_params = {"username": "ghost"}
        with mock.patch(f"{STORE}.load_store", return_value={}):
            ops_h._get_operator_passkeys(h, {})
        assert h.errors[0][0] == 404

    def test_list_gate_denied_maps(self):
        h = _Handler()
        h._api_params = {"username": "alice"}
        exc = decision.UseCaseError(decision.ERR_PERMISSION, "not yours")
        with (
            mock.patch(f"{STORE}.load_store", return_value={"alice": {}}),
            mock.patch(f"{PASSKEYS}.gate_manage", side_effect=exc),
        ):
            ops_h._get_operator_passkeys(h, {})
        assert h.errors[0][0] == 403

    def test_register_begin_delegates_actor(self):
        h = _Handler()
        h._api_params = {"username": "alice"}
        with mock.patch(f"{PASSKEYS}.begin_registration", return_value={"challenge": "c"}):
            ops_h._post_passkey_register_begin(h, {})
        assert h.sent[0][1]["data"]["options"] == {"challenge": "c"}

    def test_rename_delegates_with_perms(self):
        h = _json_handler({"name": "yubikey"})
        h._api_params = {"username": "alice", "credential_ref": "ref1"}
        with mock.patch(f"{PASSKEYS}.rename_passkey") as rn:
            ops_h._patch_passkey(h, {})
        assert rn.call_args.args[3] == "ref1"
        assert h.sent[0][1]["data"] == {"renamed": True}

    def test_delete_passkey_delegates(self):
        h = _Handler()
        h._api_params = {"username": "alice", "credential_ref": "ref1"}
        with mock.patch(f"{PASSKEYS}.delete_passkey") as dp:
            ops_h._delete_passkey(h, {})
        dp.assert_called_once()
        assert h.sent[0][1]["data"] == {"deleted": True}
