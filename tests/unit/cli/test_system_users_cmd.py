"""Unit tests for cli.commands.system_users — system-user create/delete."""

import os
import sys
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.cli.commands import system_users as su  # noqa: E402
from vnc_remote_secure.engine.application import system_users  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_LAST_ADMIN,
    UseCaseError,
)


def _args(action, **over):
    base = {"system_user_action": action, "username": "bob", "json": False, "dry_run": False}
    base.update(over)
    return Namespace(**base)


class TestSystemUserCreate:
    def test_create_ok(self, monkeypatch, capsys):
        monkeypatch.setattr(su, "_prompt_password", lambda confirm=True: "s3cret!")
        seen = {}
        monkeypatch.setattr(
            system_users,
            "create_system_user",
            lambda actor, username, password: seen.update(actor=actor, username=username)
            or {"username": username},
        )
        assert su.cmd_system_user(_args("create")) == 0
        assert seen["username"] == "bob"
        assert seen["actor"].startswith("cli:")
        assert "created" in capsys.readouterr().out

    def test_create_use_case_error(self, monkeypatch, capsys):
        monkeypatch.setattr(su, "_prompt_password", lambda confirm=True: "s3cret!")

        def _deny(actor, username, password):
            raise UseCaseError(ERR_LAST_ADMIN, "Cannot create")

        monkeypatch.setattr(system_users, "create_system_user", _deny)
        assert su.cmd_system_user(_args("create")) == 1
        assert "Cannot create" in capsys.readouterr().err

    def test_dry_run_skips_use_case(self, monkeypatch, capsys):
        monkeypatch.setattr(su, "_prompt_password", lambda confirm=True: "s3cret!")
        monkeypatch.setattr(
            system_users,
            "create_system_user",
            lambda *a: (_ for _ in ()).throw(AssertionError("must not run")),
        )
        assert su.cmd_system_user(_args("create", dry_run=True)) == 0
        assert "DRY RUN" in capsys.readouterr().out


class TestSystemUserDelete:
    def test_delete_ok(self, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(
            system_users, "delete_system_user", lambda actor, username: seen.append(username)
        )
        assert su.cmd_system_user(_args("delete")) == 0
        assert seen == ["bob"]
        assert "deleted" in capsys.readouterr().out

    def test_delete_protected(self, monkeypatch, capsys):
        def _deny(actor, username):
            raise UseCaseError(ERR_LAST_ADMIN, "Cannot delete")

        monkeypatch.setattr(system_users, "delete_system_user", _deny)
        assert su.cmd_system_user(_args("delete")) == 1
        assert "Cannot delete" in capsys.readouterr().err

    def test_unknown_action(self):
        assert su.cmd_system_user(_args("frobnicate")) == 1
