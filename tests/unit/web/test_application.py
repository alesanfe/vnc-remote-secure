"""Unit tests for web.application — the FastAPI health app factory."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

pytest.importorskip('fastapi')

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from vnc_remote_secure.web.application import create_app  # noqa: E402


def test_create_app_returns_fastapi():
    """create_app returns the ASGI health application."""
    app = create_app({})
    assert isinstance(app, FastAPI)


def test_create_app_registers_health_routes():
    """The app carries the machine-facing surface — no user pages."""
    app = create_app({})
    paths = {r.path for r in app.routes}
    assert '/health' in paths
    assert '/health/live' in paths
    assert '/health/ready' in paths
    assert '/health/services' in paths
    assert '/health/all' in paths
    assert '/metrics' in paths
    assert '/audit' in paths
    assert '/audit/verify' in paths
    # No user-facing surface — that's the landing SPA.
    assert not any('/users' in p or '/landing' in p for p in paths)


def test_health_requires_auth_with_token(monkeypatch):
    """With HEALTH_AUTH_TOKEN set, /health denies unauthenticated
    requests even on loopback."""
    monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'good-token')
    client = TestClient(create_app({}))
    resp = client.get('/health')
    assert resp.status_code == 401
    assert resp.headers.get('WWW-Authenticate') == 'Bearer realm="Health"'


def test_security_headers_present(monkeypatch):
    monkeypatch.delenv('SECURITY_PROFILE', raising=False)
    monkeypatch.setenv('HEALTH_AUTH_TOKEN', 'good-token')
    client = TestClient(create_app({}))
    resp = client.get('/health', headers={
        'Authorization': 'Bearer good-token'})
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert 'Content-Security-Policy' in resp.headers
