"""Unit tests for cli.commands.recordings — desktop screenshot and
recording list/download/start/stop/delete dispatch."""

import json
import os
import sys
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.cli.commands.recordings import (  # noqa: E402
    cmd_desktop,
    cmd_recording,
)
from vnc_remote_secure.engine.application import recordings  # noqa: E402


def _dargs(**over):
    base = {"desktop_action": "screenshot", "output": None, "json": False, "dry_run": False}
    base.update(over)
    return Namespace(**base)


def _rargs(action, **over):
    base = {
        "recording_action": action,
        "recording_id": "rec-1",
        "output": None,
        "json": False,
        "dry_run": False,
    }
    base.update(over)
    return Namespace(**base)


class TestScreenshot:
    def test_writes_png(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(recordings, "screenshot", lambda actor: b"\x89PNG-data")
        out = tmp_path / "shot.png"
        assert cmd_desktop(_dargs(output=str(out))) == 0
        assert out.read_bytes() == b"\x89PNG-data"
        assert "saved" in capsys.readouterr().out

    def test_failure_returns_1(self, monkeypatch, capsys):
        def _boom(actor):
            raise RuntimeError("vnc unreachable")

        monkeypatch.setattr(recordings, "screenshot", _boom)
        assert cmd_desktop(_dargs()) == 1
        assert "screenshot failed" in capsys.readouterr().err

    def test_unknown_action(self):
        assert cmd_desktop(_dargs(desktop_action="frobnicate")) == 1


class TestRecordingList:
    def test_empty(self, monkeypatch, capsys):
        monkeypatch.setattr(recordings, "list_recordings", lambda: [])
        assert cmd_recording(_rargs("list")) == 0
        assert "No recordings" in capsys.readouterr().out

    def test_rows_and_state(self, monkeypatch, capsys):
        recs = [
            {
                "id": "rec_1",
                "size": 100,
                "width": 1920,
                "height": 1080,
                "running": True,
                "ended": False,
                "operator": "cli:me",
            },
            {
                "id": "rec_2",
                "size": 50,
                "width": 800,
                "height": 600,
                "running": False,
                "ended": True,
                "operator": "api:x",
            },
        ]
        monkeypatch.setattr(recordings, "list_recordings", lambda: recs)
        assert cmd_recording(_rargs("list")) == 0
        out = capsys.readouterr().out
        assert "rec_1" in out and "running" in out
        assert "rec_2" in out and "ended" in out

    def test_json(self, monkeypatch, capsys):
        monkeypatch.setattr(recordings, "list_recordings", lambda: [{"id": "rec_1"}])
        assert cmd_recording(_rargs("list", json=True)) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["recordings"][0]["id"] == "rec_1"


class TestRecordingDownload:
    def test_writes_blob(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(recordings, "read", lambda rid, actor: (b"blob", "rec-1.vrsrec"))
        out = tmp_path / "dl.vrsrec"
        args = _rargs("download", output=str(out))
        assert cmd_recording(args) == 0
        assert out.read_bytes() == b"blob"

    def test_not_found(self, monkeypatch, capsys):
        def _nf(rid, actor):
            raise FileNotFoundError(rid)

        monkeypatch.setattr(recordings, "read", _nf)
        assert cmd_recording(_rargs("download")) == 1
        assert "not found" in capsys.readouterr().err

    def test_bad_id(self, monkeypatch, capsys):
        def _bad(rid, actor):
            raise ValueError("bad recording id")

        monkeypatch.setattr(recordings, "read", _bad)
        assert cmd_recording(_rargs("download")) == 1
        assert "bad recording id" in capsys.readouterr().err


class TestRecordingStart:
    def test_start(self, monkeypatch, capsys):
        monkeypatch.setattr(recordings, "start", lambda actor: {"id": "rec_9", "running": True})
        assert cmd_recording(_rargs("start")) == 0
        assert "rec_9" in capsys.readouterr().out

    def test_dry_run_skips_use_case(self, monkeypatch, capsys):
        def _start(actor):
            raise AssertionError("must not run")

        monkeypatch.setattr(recordings, "start", _start)
        assert cmd_recording(_rargs("start", dry_run=True)) == 0
        assert "DRY RUN" in capsys.readouterr().out


class TestRecordingStop:
    def test_stop(self, monkeypatch, capsys):
        monkeypatch.setattr(recordings, "stop", lambda rid, actor: {"id": rid, "running": False})
        assert cmd_recording(_rargs("stop")) == 0
        assert "stopped" in capsys.readouterr().out

    def test_not_running(self, monkeypatch, capsys):
        def _nf(rid, actor):
            raise FileNotFoundError(rid)

        monkeypatch.setattr(recordings, "stop", _nf)
        assert cmd_recording(_rargs("stop")) == 1
        assert "not running" in capsys.readouterr().err


class TestRecordingDelete:
    def test_delete(self, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(
            recordings,
            "delete",
            lambda rid, actor, auth_ctx=None: seen.append(rid) or {"deleted": rid},
        )
        assert cmd_recording(_rargs("delete")) == 0
        assert seen == ["rec-1"]
        assert "deleted" in capsys.readouterr().out

    def test_not_found(self, monkeypatch, capsys):
        def _nf(rid, actor, auth_ctx=None):
            raise FileNotFoundError(rid)

        monkeypatch.setattr(recordings, "delete", _nf)
        assert cmd_recording(_rargs("delete")) == 1

    def test_still_running_conflict(self, monkeypatch, capsys):
        def _live(rid, actor, auth_ctx=None):
            raise RuntimeError("recording still running")

        monkeypatch.setattr(recordings, "delete", _live)
        assert cmd_recording(_rargs("delete")) == 1
        assert "still running" in capsys.readouterr().err

    def test_unknown_action(self):
        assert cmd_recording(_rargs("frobnicate")) == 1
