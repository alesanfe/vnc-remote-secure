"""Unit tests for services.vnc module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.services.vnc import start_vnc, stop_vnc

def test_start_vnc_returns_dict():
    """VNC start should return a status dict (stub test)."""
    result = start_vnc(display=1, geometry="1280x720", depth=24, password="test")
    assert isinstance(result, dict)
