"""Unit tests for services.audio module.

External dependencies (ffmpeg, platform adapter, subprocess) are mocked
so the tests are deterministic and do not require ffmpeg to be installed.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services import audio


class _FakeAdapter:
    """Fake platform adapter for audio tests."""
    def __init__(self, input_args=None, devices_output=""):
        self._input_args = input_args or ["-f", "alsa", "-i", "default"]
        self._devices_output = devices_output

    def get_audio_capture_cmd(self, ffmpeg, device, bitrate):
        return self._input_args

    def list_audio_devices(self, ffmpeg):
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
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: None)
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
    assert "-f" in cmd and "alsa" in cmd
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
    assert "-f" in cmd and "avfoundation" in cmd


# ---------------------------------------------------------------------------
# list_audio_devices
# ---------------------------------------------------------------------------

def test_list_audio_devices_no_ffmpeg(monkeypatch, caplog):
    """list_audio_devices logs an error when ffmpeg is missing."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: None)
    audio.list_audio_devices()
    assert any("ffmpeg not found" in r.message for r in caplog.records)


def test_list_audio_devices_uses_adapter(monkeypatch, caplog):
    """list_audio_devices delegates to the platform adapter."""
    monkeypatch.setattr(audio, 'find_ffmpeg', lambda: "ffmpeg")
    _patch_adapter(
        monkeypatch,
        _FakeAdapter(devices_output="hw:0 (ALSA capture device)")
    )
    audio.list_audio_devices()
    # Should not raise; adapter output is logged via logger.info
