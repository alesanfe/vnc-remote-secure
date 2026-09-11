"""Integration test: platform detection on Windows."""
import os
import sys
import platform
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.platform.detection import detect_platform, is_linux, is_windows

@pytest.mark.skipif(platform.system() != 'Windows', reason='Windows only')
def test_detects_windows():
    assert detect_platform() == 'windows'
    assert is_windows() is True
    assert is_linux() is False
