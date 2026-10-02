"""System-user use case guards: reserved/current account protection,
username+password policy runs before the platform adapter, audit."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.engine.application import system_users  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_INVALID,
    ERR_LAST_ADMIN,
    ERR_PERMISSION,
    UseCaseError,
)


@pytest.fixture
def env(monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores

    state = {
        "reserved": {"root", "administrator", "system"},
        "current": "svc-vnc",
        "created": [],
        "deleted": [],
        "audits": [],
        "jobs": [],
    }
    monkeypatch.setattr(stores, "system_usernames_reserved", lambda: state["reserved"])
    monkeypatch.setattr(stores, "system_current_user", lambda: state["current"])
    monkeypatch.setattr(stores, "system_user_create", lambda u, p: state["created"].append(u))
    monkeypatch.setattr(stores, "system_user_delete", lambda u: state["deleted"].append(u) or True)
    monkeypatch.setattr(
        stores, "audit", lambda ev, user, detail="", result="": state["audits"].append((ev, result))
    )
    monkeypatch.setattr(stores, "job_start", lambda *a: "jid-1")
    monkeypatch.setattr(stores, "job_fail", lambda j, m="": state["jobs"].append(("fail", j)))
    monkeypatch.setattr(stores, "job_finish", lambda j, m="": state["jobs"].append(("finish", j)))
    return state


# --- create ------------------------------------------------------------------


def test_create_reserved_refused(env):
    # 'administrator' passes validate_username — the RESERVED check
    # is what must refuse it (policy, not syntax).
    with pytest.raises(UseCaseError) as exc:
        system_users.create_system_user("root", "administrator", "S3cret-Pass!")
    assert exc.value.code == ERR_PERMISSION
    assert env["created"] == []
    assert env["audits"][-1][0] == "api_permission_denied"


def test_create_invalid_username(env):
    for bad in ("-bad", "a" * 64, "with space"):
        with pytest.raises(UseCaseError) as exc:
            system_users.create_system_user("root", bad, "S3cret-Pass!")
        assert exc.value.code == ERR_INVALID
    assert env["created"] == []


def test_create_weak_password_refused(env):
    with pytest.raises(UseCaseError):
        system_users.create_system_user("root", "newuser", "short")
    assert env["created"] == []


def test_create_ok_audited(env):
    out = system_users.create_system_user("root", "newuser", "S3cret-Passw0rd!")
    assert out["username"] == "newuser"
    assert env["created"] == ["newuser"]
    assert env["audits"][-1] == ("user_create", "")
    assert env["jobs"][-1][0] == "finish"


def test_create_adapter_failure_marks_job(env, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores

    def _boom(u, p):
        raise OSError("net user failed")

    monkeypatch.setattr(stores, "system_user_create", _boom)
    with pytest.raises(UseCaseError) as exc:
        system_users.create_system_user("root", "newuser", "S3cret-Passw0rd!")
    assert exc.value.code == ERR_INVALID
    assert env["jobs"] == [("fail", "jid-1")]
    assert env["audits"][-1] == ("user_create", "failure")


# --- delete ------------------------------------------------------------------


def test_delete_reserved_refused(env):
    with pytest.raises(UseCaseError) as exc:
        system_users.delete_system_user("root", "administrator")
    assert exc.value.code == ERR_LAST_ADMIN
    assert env["deleted"] == []


def test_delete_current_process_account_refused(env):
    with pytest.raises(UseCaseError) as exc:
        system_users.delete_system_user("root", "svc-vnc")
    assert exc.value.code == ERR_LAST_ADMIN


def test_delete_ok(env):
    system_users.delete_system_user("root", "olduser")
    assert env["deleted"] == ["olduser"]
    assert env["audits"][-1] == ("user_delete", "")
    assert env["jobs"][-1][0] == "finish"


def test_delete_adapter_false_fails_job(env, monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores

    monkeypatch.setattr(stores, "system_user_delete", lambda u: False)
    with pytest.raises(UseCaseError):
        system_users.delete_system_user("root", "olduser")
    assert env["jobs"] == [("fail", "jid-1")]
