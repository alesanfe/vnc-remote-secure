"""Unit tests for web.application module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.web.application import create_app

def test_create_app_returns_object():
    """create_app should return a web application object."""
    app = create_app({})
    assert app is not None
