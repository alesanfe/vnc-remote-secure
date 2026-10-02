"""Unit tests for the use-case-backed ``operator`` sub-actions
(restore, revoke-sessions) — tombstone/last-admin rules live in the
shared use case, the CLI only dispatches."""

import os
import sys
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.cli.commands.operator import cmd_operator  # noqa: E402
from vnc_remote_secure.engine.application import operators  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_NOT_FOUND,
    UseCaseError,
)


def _args(action, **over):
    base = {
        "operator_action": action,
        "username": "alice",
        "role": "viewer",
        "json": False,
        "dry_run": False,
    }
    base.update(over)
    return Namespace(**base)


class TestOperatorRestore:
    def test_restore_ok(self, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(
            operators,
            "restore_operator",
            lambda actor, username: seen.append(username) or {"username": username},
        )
        assert cmd_operator(_args("restore")) == 0
        assert seen == ["alice"]
        assert "restored" in capsys.readouterr().out

    def test_restore_no_tombstone(self, monkeypatch, capsys):
        def _nf(actor, username):
            raise UseCaseError(ERR_NOT_FOUND, "no deleted account for this username")

        monkeypatch.setattr(operators, "restore_operator", _nf)
        assert cmd_operator(_args("restore")) == 1
        assert "no deleted account" in capsys.readouterr().out


class TestOperatorRevokeSessions:
    def test_revoke_ok(self, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(
            operators, "revoke_sessions", lambda actor, username: seen.append(username)
        )
        assert cmd_operator(_args("revoke-sessions")) == 0
        assert seen == ["alice"]
        assert "revoked" in capsys.readouterr().out

    def test_revoke_not_found(self, monkeypatch, capsys):
        def _nf(actor, username):
            raise UseCaseError(ERR_NOT_FOUND, "operator not found")

        monkeypatch.setattr(operators, "revoke_sessions", _nf)
        assert cmd_operator(_args("revoke-sessions")) == 1
        assert "not found" in capsys.readouterr().out
