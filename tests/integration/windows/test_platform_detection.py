"""Integration test: platform detection on Windows.

The real-platform test is skipped on non-Windows. The parametrized
test uses monkeypatch to simulate Windows on any host so the logic
is exercised everywhere.
"""
import os
import platform
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.platform.detection import detect_platform, is_linux, is_windows


@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows only')
def test_detects_windows():
    assert detect_platform() == 'windows'
    assert is_windows() is True
    assert is_linux() is False


def test_detects_windows_with_mock(monkeypatch):
    """detect_platform returns 'windows' when platform.system() is mocked to Windows."""
    monkeypatch.setattr(platform, 'system', lambda: 'Windows')
    assert detect_platform() == 'windows'
    assert is_windows() is True
    assert is_linux() is False
