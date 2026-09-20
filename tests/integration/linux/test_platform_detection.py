"""Integration test: platform detection on Linux.

The real-platform test asserts the detected platform matches the
host's ``platform.system()`` — on a Linux host it verifies 'linux',
on Windows 'windows'. The parametrized test uses monkeypatch to
simulate Linux on any host so the Linux code path is exercised
everywhere.
"""
import os
import platform
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.platform.detection import detect_platform, is_linux, is_windows


def test_detects_current_platform():
    """detect_platform agrees with platform.system() on the real host."""
    expected = {
        'windows': 'windows',
        'linux': 'linux',
        'darwin': 'macos',
    }[platform.system().lower()]
    assert detect_platform() == expected
    assert is_windows() == (expected == 'windows')
    assert is_linux() == (expected == 'linux')


def test_detects_linux_with_mock(monkeypatch):
    """detect_platform returns 'linux' when platform.system() is mocked to Linux."""
    monkeypatch.setattr(platform, 'system', lambda: 'Linux')
    assert detect_platform() == 'linux'
    assert is_linux() is True
    assert is_windows() is False
