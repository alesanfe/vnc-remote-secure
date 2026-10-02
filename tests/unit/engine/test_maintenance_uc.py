"""Maintenance use case: drain_timeout bounds, deferred drain_at,
immediate drain sweep count, audit emission."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.engine.application import maintenance  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_INVALID,
    UseCaseError,
)


@pytest.fixture
def env(monkeypatch):
    from vnc_remote_secure.engine.infrastructure import stores

    state = {"set": [], "drained": 0, "audits": [], "active": True}
    monkeypatch.setattr(
        stores,
        "maintenance_set",
        lambda active, by="", reason="", drain_at=None: state["set"].append(
            {"active": active, "by": by, "reason": reason, "drain_at": drain_at}
        ),
    )
    monkeypatch.setattr(stores, "maintenance_drain", lambda: 3)
    monkeypatch.setattr(
        stores, "audit", lambda ev, user, detail="": state["audits"].append((ev, user, detail))
    )
    monkeypatch.setattr(stores, "maintenance_active", lambda: state["active"])
    monkeypatch.setattr(stores, "maintenance_info", lambda: {"source": "flag-file"})
    return state


def test_drain_timeout_out_of_range(env):
    with pytest.raises(UseCaseError) as exc:
        maintenance.set_maintenance("root", True, drain_timeout=-1)
    assert exc.value.code == ERR_INVALID
    with pytest.raises(UseCaseError):
        maintenance.set_maintenance("root", True, drain_timeout=24 * 3600 + 1)
    assert env["set"] == []


def test_drain_timeout_schedules_deferred(env):
    out = maintenance.set_maintenance("root", True, drain_timeout=300)
    assert env["set"][0]["drain_at"] is not None
    assert out["drained_now"] == 0  # not drained now
    assert out["drain_at"] > 0


def test_drain_flag_sweeps_immediately(env):
    out = maintenance.set_maintenance("root", True, drain=True)
    assert out["drained_now"] == 3
    assert "drained=3" in env["audits"][-1][2]


def test_disable_emits_audit(env):
    maintenance.set_maintenance("root", False)
    ev, user, detail = env["audits"][-1]
    assert ev == "maintenance_changed" and "active=0" in detail


def test_reason_truncated(env):
    maintenance.set_maintenance("root", True, reason="x" * 500)
    assert len(env["set"][0]["reason"]) == 256
