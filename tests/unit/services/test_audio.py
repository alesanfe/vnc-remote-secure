"""Unit tests for services.audio module.

External dependencies (ffmpeg, platform adapter, subprocess) are mocked
so the tests are deterministic and do not require ffmpeg to be installed.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import audio


class _FakeAdapter:
    """Fake platform adapter for audio tests."""
    def __init__(self, input_args=None, devices_output=""):
        self._input_args = input_args or ["-f", "alsa", "-i", "default"]
        self._devices_output = devices_output
        self.list_devices_called_with = []

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        return self._input_args

    def list_audio_devices(self, ffmpeg):
        self.list_devices_called_with.append(ffmpeg)
        if self._devices_output:
            import logging
            logging.getLogger(__name__).info("%s", self._devices_output)


def _patch_adapter(monkeypatch, adapter):
    """Patch get_adapter() to return the given fake adapter."""
    def _fake_get_adapter():
        return adapter
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', _fake_get_adapter
    )


# ---------------------------------------------------------------------------
# find_ffmpeg
# ---------------------------------------------------------------------------

def test_find_ffmpeg_returns_binary_when_available(monkeypatch):
    """find_ffmpeg returns 'ffmpeg' when the binary responds to -version."""
    import subprocess
    monkeypatch.setattr(
        subprocess, 'run',
        lambda *a, **k: subprocess.CompletedProcess(
            a[0] if a else [], returncode=0))
    assert audio.find_ffmpeg() == "ffmpeg"


def test_find_ffmpeg_returns_none_when_missing(monkeypatch):
    """find_ffmpeg returns None when ffmpeg is not on PATH."""
    import subprocess

    def _raise(*a, **k):
        raise FileNotFoundError("ffmpeg not found")
    monkeypatch.setattr(subprocess, 'run', _raise)
    assert audio.find_ffmpeg() is None


def test_find_ffmpeg_returns_none_on_timeout(monkeypatch):
    """find_ffmpeg returns None when ffmpeg times out."""
    import subprocess

    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ffmpeg", timeout=5)
    monkeypatch.setattr(subprocess, 'run', _raise)
    assert audio.find_ffmpeg() is None


# ---------------------------------------------------------------------------
# get_ffmpeg_capture_cmd
# ---------------------------------------------------------------------------

def test_get_ffmpeg_capture_cmd_returns_none_without_ffmpeg(monkeypatch):
    """get_ffmpeg_capture_cmd returns None when ffmpeg is not found."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: None)
    assert audio.get_ffmpeg_capture_cmd() is None


def test_get_ffmpeg_capture_cmd_uses_adapter_args(monkeypatch):
    """get_ffmpeg_capture_cmd builds a command using the platform adapter."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: "ffmpeg")
    _patch_adapter(monkeypatch, _FakeAdapter(input_args=["-f", "alsa", "-i", "hw:0"]))

    cmd = audio.get_ffmpeg_capture_cmd(device="hw:0", bitrate=192)
    assert cmd is not None
    assert cmd[0] == "ffmpeg"
    assert "-f" in cmd
    assert "alsa" in cmd
    assert "-codec:a" in cmd
    assert "libmp3lame" in cmd
    assert "-b:a" in cmd
    assert "192k" in cmd
    assert "pipe:1" in cmd


def test_get_ffmpeg_capture_cmd_falls_back_to_avfoundation(monkeypatch):
    """get_ffmpeg_capture_cmd falls back to avfoundation when adapter fails."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: "ffmpeg")

    def _raise():
        raise RuntimeError("adapter unavailable")
    monkeypatch.setattr(
        'vnc_remote_secure.platform.base.get_adapter', _raise
    )

    cmd = audio.get_ffmpeg_capture_cmd(device=None, bitrate=128)
    assert cmd is not None
    assert "-f" in cmd
    assert "avfoundation" in cmd


# ---------------------------------------------------------------------------
# list_audio_devices
# ---------------------------------------------------------------------------

def test_list_audio_devices_no_ffmpeg(monkeypatch, caplog):
    """list_audio_devices logs an error when ffmpeg is missing."""
    # Ensure capture works even if a prior test called setup_logging()
    # (which sets propagate=False on the vnc_remote_secure logger).
    import logging as _logging
    _logging.getLogger('vnc_remote_secure').propagate = True
    caplog.set_level(_logging.ERROR, logger='vnc_remote_secure.services.audio')
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: None)
    audio.list_audio_devices()
    assert any("ffmpeg not found" in r.message for r in caplog.records)


def test_list_audio_devices_uses_adapter(monkeypatch, caplog):
    """list_audio_devices delegates to the platform adapter."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: "ffmpeg")
    adapter = _FakeAdapter(devices_output="hw:0 (ALSA capture device)")
    _patch_adapter(monkeypatch, adapter)
    audio.list_audio_devices()
    # The resolved ffmpeg path must reach the adapter's device listing.
    assert adapter.list_devices_called_with == ["ffmpeg"]


class TestAudioToctouRevoke:
    """register_websocket_connection -> None (session revoked between
    the gateway check and registration) must close with 1008."""

    def test_revoked_between_check_and_register(self, monkeypatch):
        import asyncio

        from vnc_remote_secure.services import audio
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.check_websocket_upgrade',
            lambda **kw: (True, 'OK'), raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
            lambda *a, **kw: None, raising=False)

        class _WS:
            remote_address = ('127.0.0.1', 1)
            request_headers = {}
            closed_with = None

            async def close(self, code=None, reason=None):
                self.closed_with = (code, reason)

            async def send(self, m):
                pass

        ws = _WS()
        server = audio.AudioStreamServer('127.0.0.1', 0, None, 128)
        asyncio.run(server.handle_client(ws))
        # Strict: the revoked-session path MUST close with 1008.
        assert ws.closed_with == (1008, 'Session revoked')


class TestAudioFfmpegFailure:
    """start_ffmpeg failing must close 1011 and unregister the
    connection — a dead capture must not leave an open, registered
    socket."""

    def test_ffmpeg_fail_closes_1011_unregisters(self, monkeypatch):
        import asyncio

        from vnc_remote_secure.services import audio
        unreg = []
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.register_websocket_connection',
            lambda *a, **kw: 'conn_1', raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.auth_gateway.unregister_websocket_connection',
            lambda cid: unreg.append(cid), raising=False)
        monkeypatch.setattr(
            'vnc_remote_secure.security.websocket_registry.'
            'start_revocation_watcher', lambda t: None, raising=False)

        class _WS:
            remote_address = ('127.0.0.1', 1)
            request_headers = {}
            closed_with = None

            async def close(self, code=None, reason=None):
                self.closed_with = (code, reason)

            async def send(self, m):
                pass

        ws = _WS()
        server = audio.AudioStreamServer('127.0.0.1', 0, None, 128)
        server._ffmpeg_lock = asyncio.Lock()
        from unittest import mock
        with mock.patch.object(server, '_authenticate_ws',
                               new=mock.AsyncMock(return_value='tok')), \
             mock.patch.object(server, 'start_ffmpeg',
                               new=mock.AsyncMock(return_value=False)):
            asyncio.run(server.handle_client(ws))
        assert ws.closed_with == (1011, 'Audio capture failed')
        assert 'conn_1' in unreg
        assert ws not in server.clients
