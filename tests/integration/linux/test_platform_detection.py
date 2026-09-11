"""Integration test: platform detection on Linux."""
import os
import sys
import platform
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.platform.detection import detect_platform, is_linux, is_windows

@pytest.mark.skipif(platform.system() != 'Linux', reason='Linux only')
def test_detects_linux():
    assert detect_platform() == 'linux'
    assert is_linux() is True
    assert is_windows() is False
