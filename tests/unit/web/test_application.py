"""Unit tests for web.application module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.web.application import create_app, SimpleWebApp


def test_create_app_returns_flask_when_available():
    """create_app returns a Flask app when Flask is installed."""
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed; fallback app is tested separately")
    app = create_app({})
    assert isinstance(app, Flask)


def test_create_app_registers_blueprints():
    """Flask app should register the expected blueprints."""
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed")
    app = create_app({})
    rules = {r.endpoint for r in app.url_map.iter_rules()}
    # health_bp, landing_bp, users_bp register endpoints containing these names.
    assert any('health' in r for r in rules)
    assert any('landing' in r for r in rules)
    assert any('user' in r for r in rules)


def test_create_app_has_secret_key():
    """Flask app must have a non-empty secret_key."""
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed")
    app = create_app({})
    assert app.secret_key
    assert len(app.secret_key) > 0


def test_create_app_stores_config():
    """Flask app should expose the provided config under VNC_CONFIG."""
    try:
        from flask import Flask
    except ImportError:
        pytest.skip("Flask not installed")
    cfg = {'vnc_port': 9999, 'custom': True}
    app = create_app(cfg)
    assert app.config.get('VNC_CONFIG') is cfg


def test_fallback_app_serves_health():
    """SimpleWebApp should serve JSON at /health."""
    app = SimpleWebApp({})
    captured = {}
    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)
    body = b''.join(app({'PATH_INFO': '/health', 'REQUEST_METHOD': 'GET'}, start_response))
    assert captured['status'].startswith('200')
    assert 'application/json' in captured['headers'].get('Content-Type', '')
    import json
    data = json.loads(body)
    assert 'status' in data


def test_fallback_app_serves_text_for_other_paths():
    """SimpleWebApp should serve a text page for non-health paths."""
    app = SimpleWebApp({})
    captured = {}
    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)
    body = b''.join(app({'PATH_INFO': '/', 'REQUEST_METHOD': 'GET'}, start_response))
    assert captured['status'].startswith('200')
    assert 'text/plain' in captured['headers'].get('Content-Type', '')
    assert b'Flask' in body
