"""OpenAPI contract gates for docs/api/openapi.v1.yaml.

Two layers:

1. ``openapi_spec_validator`` proves the document itself is a valid
   OpenAPI 3.x spec — broken ``$ref``s, malformed schemas, missing
   responses fail here even when the drift test passes.
2. ``openapi_core`` validates real HTTP responses against the spec —
   a handler returning an undeclared field, a wrong type or an
   unexpected status breaks the contract at test time instead of at
   consumer time.
"""
import os

import pytest

pytestmark = pytest.mark.timeout(90)

_SPEC_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', '..',
    'docs', 'api', 'openapi.v1.yaml')


@pytest.fixture
def server(monkeypatch, tmp_path, asgi_server):
    """Minimal portal app — the same fixture shape as test_api_v1."""
    from vnc_remote_secure.services import landing
    monkeypatch.setenv('LANDING_PASSWORD', 'T3st-Landing!Pass')
    monkeypatch.setattr(landing, 'check_port', lambda *a, **k: True)
    monkeypatch.setattr(landing, 'get_lan_ips', lambda: ['10.0.0.9'])
    monkeypatch.setattr(
        landing, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    from vnc_remote_secure.core import portal as cp
    monkeypatch.setattr(cp, 'check_port', lambda *a, **k: True)
    monkeypatch.setattr(cp, 'get_lan_ips', lambda: ['10.0.0.9'])
    monkeypatch.setattr(
        cp, 'get_system_metrics',
        lambda: {'hostname': 'h', 'os': 'os', 'uptime': '1h',
                 'cpu': '1%', 'memory': '2G', 'disk': '3G'})
    cfg = {
        'novnc_port': 6080, 'ttyd_port': 7681, 'health_port': 8080,
        'landing_port': 8000, 'vnc_port': 5900, 'vnc_http_port': 5800,
        'novnc_host': '127.0.0.1', 'ttyd_host': '127.0.0.1',
        'health_host': '127.0.0.1',
    }
    monkeypatch.setattr(landing, '_config', lambda: cfg)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        from vnc_remote_secure.backend.app import create_app
        yield asgi_server(create_app())
    finally:
        os.chdir(cwd)


def _base(server):
    return f'http://127.0.0.1:{server}'


def _spec():
    openapi_core = pytest.importorskip('openapi_core')
    return openapi_core.OpenAPI.from_file_path(_SPEC_PATH)


def _validate(spec, method, url, resp, json_body=None):
    import requests
    from openapi_core.contrib.requests import (
        RequestsOpenAPIRequest,
        RequestsOpenAPIResponse,
    )
    req = RequestsOpenAPIRequest(
        requests.Request(method, url, json=json_body).prepare())
    spec.validate_response(req, RequestsOpenAPIResponse(resp))


def test_openapi_v1_document_is_valid():
    """The published spec must satisfy the OpenAPI metaschema."""
    import yaml
    openapi_spec_validator = pytest.importorskip('openapi_spec_validator')
    with open(_SPEC_PATH, encoding='utf-8') as fh:
        spec_dict = yaml.safe_load(fh)
    openapi_spec_validator.validate(spec_dict)


def test_me_response_matches_openapi_contract(server):
    """GET /me response validates against the spec (401 anonymous)."""
    import requests

    url = _base(server) + '/api/v1/me'
    resp = requests.get(url, timeout=10)
    _validate(_spec(), 'GET', url, resp)


def test_login_error_envelope_matches_contract(server):
    """POST /auth/login failure envelope validates against the spec."""
    import requests

    url = _base(server) + '/api/v1/auth/login'
    body = {'username': 'nobody', 'password': 'wrong'}
    resp = requests.post(url, json=body, timeout=10)
    assert resp.status_code in (401, 403, 429)
    _validate(_spec(), 'POST', url, resp, json_body=body)
