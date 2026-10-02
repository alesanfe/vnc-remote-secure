"""Unit tests for cli.commands.power — host power + Wake-on-LAN."""

import os
import sys
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.cli.commands.power import cmd_power  # noqa: E402
from vnc_remote_secure.engine.application import power  # noqa: E402


def _args(action, **over):
    base = {
        "power_action": action,
        "action": "restart",
        "yes": False,
        "mac": "AA:BB:CC:DD:EE:FF",
        "broadcast": "255.255.255.255",
        "port": 9,
        "json": False,
        "dry_run": False,
    }
    base.update(over)
    return Namespace(**base)


class TestPowerAction:
    def test_yes_schedules(self, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(
            power,
            "host_power",
            lambda action, actor, auth_ctx=None: seen.append(action)
            or {"action": action, "accepted": True, "effective_in_seconds": 1.0},
        )
        assert cmd_power(_args("action", yes=True)) == 0
        assert seen == ["restart"]
        assert "scheduled" in capsys.readouterr().out

    def test_confirm_abort(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda *a: "n")
        monkeypatch.setattr(
            power,
            "host_power",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")),
        )
        assert cmd_power(_args("action")) == 1
        assert "Aborted" in capsys.readouterr().out

    def test_confirm_accept(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *a: "y")
        seen = []
        monkeypatch.setattr(
            power,
            "host_power",
            lambda action, actor, auth_ctx=None: seen.append(action)
            or {"action": action, "accepted": True, "effective_in_seconds": 1.0},
        )
        assert cmd_power(_args("action")) == 0
        assert seen == ["restart"]

    def test_confirm_eof_aborts(self, monkeypatch, capsys):
        def _eof(*a):
            raise EOFError

        monkeypatch.setattr("builtins.input", _eof)
        assert cmd_power(_args("action")) == 1
        assert "Aborted" in capsys.readouterr().out

    def test_bad_action(self, monkeypatch, capsys):
        def _bad(action, actor, auth_ctx=None):
            raise ValueError("action must be one of ...")

        monkeypatch.setattr(power, "host_power", _bad)
        assert cmd_power(_args("action", yes=True)) == 1
        assert "Error" in capsys.readouterr().err

    def test_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(
            power,
            "host_power",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")),
        )
        assert cmd_power(_args("action", dry_run=True)) == 0
        assert "DRY RUN" in capsys.readouterr().out


class TestPowerWol:
    def test_wol_ok(self, monkeypatch, capsys):
        seen = {}
        monkeypatch.setattr(
            power,
            "wake_on_lan",
            lambda mac, broadcast, port, actor="": seen.update(
                mac=mac, broadcast=broadcast, port=port
            )
            or {"sent": True, "mac": mac, "broadcast": broadcast, "port": port},
        )
        assert cmd_power(_args("wol")) == 0
        assert seen["mac"] == "AA:BB:CC:DD:EE:FF"
        assert "sent" in capsys.readouterr().out

    def test_wol_bad_mac(self, monkeypatch, capsys):
        def _bad(*a, **k):
            raise ValueError("invalid MAC address")

        monkeypatch.setattr(power, "wake_on_lan", _bad)
        assert cmd_power(_args("wol", mac="nope")) == 1
        assert "invalid MAC" in capsys.readouterr().err

    def test_unknown_action(self):
        assert cmd_power(_args("frobnicate")) == 1
