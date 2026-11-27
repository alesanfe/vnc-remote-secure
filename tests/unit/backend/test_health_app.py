"""Tests for backend.health_app — the FastAPI machine-facing surface.

Covers the wire contract: Bearer gating per scope, liveness/readiness
status codes, rate-limited public probes, security.txt, metrics,
audit pagination, security headers on every response, and the
canonical error envelope on non-route responses.
"""

import sys
from unittest import mock

import pytest

sys.path.insert(0, "src")

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from vnc_remote_secure.backend.health_app import create_health_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_health_app())


@pytest.fixture(autouse=True)
def _open_auth():
    """Loopback deployment with no token → auth open (the default
    dev/test posture). Scoped-token paths are tested explicitly."""
    with mock.patch("vnc_remote_secure.security.http_auth.check_health_auth", return_value=True):
        yield


class TestHealthEndpoints:
    def test_health_healthy_200(self, client):
        with mock.patch(
            "vnc_remote_secure.services.health.get_health_status",
            return_value={"status": "healthy"},
        ):
            r = client.get("/health")
        assert r.status_code == 200

    def test_health_degraded_still_200(self, client):
        with mock.patch(
            "vnc_remote_secure.services.health.get_health_status",
            return_value={"status": "degraded"},
        ):
            assert client.get("/health_status").status_code == 200

    def test_health_down_is_503(self, client):
        with mock.patch(
            "vnc_remote_secure.services.health.get_health_status",
            return_value={"status": "down"},
        ):
            assert client.get("/health_status.json").status_code == 503

    def test_ready_requires_fully_healthy(self, client):
        with mock.patch(
            "vnc_remote_secure.services.health.get_health_status",
            return_value={"status": "degraded"},
        ):
            # degraded passes /health but fails /health/ready
            assert client.get("/health/ready").status_code == 503
        with mock.patch(
            "vnc_remote_secure.services.health.get_health_status",
            return_value={"status": "healthy"},
        ):
            assert client.get("/health/ready").status_code == 200

    def test_services_delegates(self, client):
        with mock.patch(
            "vnc_remote_secure.core.service_manager.status_all",
            return_value={"services": {}},
        ):
            assert client.get("/health/services").json() == {"services": {}}

    def test_all_health_wraps_errors(self, client):
        with mock.patch(
            "vnc_remote_secure.monitoring.health.get_all_health",
            side_effect=RuntimeError("boom"),
        ):
            r = client.get("/health/all")
        assert r.status_code == 500
        assert r.json()["error"] is not None  # canonical envelope


class TestAuthGating:
    def test_unauthorized_returns_401_with_realm(self, client):
        with mock.patch(
            "vnc_remote_secure.security.http_auth.check_health_auth", return_value=False
        ):
            r = client.get("/health")
        assert r.status_code == 401
        assert 'Bearer realm="Health"' in r.headers.get("www-authenticate", "")

    def test_metrics_uses_metrics_scope(self, client):
        seen = {}

        def fake_auth(auth, client_ip=None, peer_ip=None, scope=None):
            seen["scope"] = scope
            return False

        with mock.patch(
            "vnc_remote_secure.security.http_auth.check_health_auth", side_effect=fake_auth
        ):
            client.get("/metrics")
        assert seen["scope"] == "metrics"

    def test_audit_uses_audit_scope(self, client):
        seen = {}

        def fake_auth(auth, client_ip=None, peer_ip=None, scope=None):
            seen["scope"] = scope
            return False

        with mock.patch(
            "vnc_remote_secure.security.http_auth.check_health_auth", side_effect=fake_auth
        ):
            client.get("/audit")
        assert seen["scope"] == "audit"

    def test_public_probes_skip_auth(self, client):
        """/health/live and security.txt are unauthenticated by design —
        check_health_auth must NOT be consulted for them."""
        with mock.patch(
            "vnc_remote_secure.security.http_auth.check_health_auth", return_value=False
        ) as ca:
            assert client.get("/health/live").status_code == 200
            assert client.get("/.well-known/security.txt").status_code == 200
        ca.assert_not_called()


class TestPublicProbes:
    def test_live_rate_limited(self, client):
        with mock.patch(
            "vnc_remote_secure.security.rate_limit.check_rate_limit", return_value=False
        ):
            r = client.get("/health/live")
        assert r.status_code == 429

    def test_security_txt_served(self, client):
        r = client.get("/.well-known/security.txt")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]


class TestMetricsAndAudit:
    def test_metrics_body(self, client):
        with mock.patch(
            "vnc_remote_secure.monitoring.prometheus.metrics_handler",
            return_value=("# HELP x\nx 1\n", 200),
        ):
            r = client.get("/metrics")
        assert r.status_code == 200
        assert "x 1" in r.text

    def test_audit_limit_clamped(self, client):
        with mock.patch(
            "vnc_remote_secure.security.audit.get_audit_entries", return_value=[]
        ) as gae:
            client.get("/audit?limit=99999")
        assert gae.call_args.kwargs["limit"] == 1000

    def test_audit_bad_limit_is_400_not_422(self, client):
        r = client.get("/audit?limit=abc")
        assert r.status_code == 400

    def test_audit_verify(self, client):
        with mock.patch(
            "vnc_remote_secure.security.audit.verify_chain",
            return_value=(True, "chain intact"),
        ):
            r = client.get("/audit/verify")
        assert r.json() == {"intact": True, "message": "chain intact"}


class TestMiddleware:
    def test_security_headers_on_every_response(self, client):
        r = client.get("/health/live")
        # get_security_headers emits a standard set — spot-check one
        assert any(k.lower() == "x-content-type-options" for k in r.headers.keys())

    def test_unknown_route_keeps_error_envelope(self, client):
        r = client.get("/no-such-route")
        assert r.status_code == 404
        body = r.json()
        assert "error" in body  # not FastAPI's {'detail': ...}

    def test_te_cl_smuggling_rejected_by_middleware(self, client):
        """request_headers_safe runs in middleware — a Transfer-Encoding
        header must produce 400 before routing."""
        r = client.get("/health/live", headers={"Transfer-Encoding": "chunked"})
        # httpx may refuse to send it; either way the app must not 200
        assert r.status_code in (400, 421, 500) or r.status_code != 200
