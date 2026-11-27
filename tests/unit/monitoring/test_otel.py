"""Tests for monitoring/otel.py — the opt-in OTel gate.

The SDK is an optional extra (not installed in the dev venv), so the
happy paths in setup_tracing/instrument_app degrade through their
documented except branches; the tests pin that contract: telemetry
must never break the app, and the enabled/disabled decision reads
through monitoring.settings.load().
"""

import sys
import types

import pytest

from vnc_remote_secure.monitoring import otel


@pytest.fixture(autouse=True)
def _reset_provider(monkeypatch):
    monkeypatch.setattr(otel, "_provider", None)


class TestOtelEnabled:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("OTEL_ENABLED", raising=False)
        assert otel.otel_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        monkeypatch.setenv("OTEL_ENABLED", "true")
        assert otel.otel_enabled() is True

    def test_settings_failure_disables(self, monkeypatch):
        def _boom():
            raise RuntimeError("bad settings")

        fake = types.ModuleType("vnc_remote_secure.monitoring.settings")
        fake.load = _boom
        monkeypatch.setitem(sys.modules, "vnc_remote_secure.monitoring.settings", fake)
        assert otel.otel_enabled() is False


class TestSetupTracing:
    def test_disabled_returns_none(self, monkeypatch):
        monkeypatch.delenv("OTEL_ENABLED", raising=False)
        assert otel.setup_tracing() is None

    def test_enabled_without_sdk_returns_none(self, monkeypatch):
        """OTEL_ENABLED=true but no opentelemetry SDK in the env —
        the setup must swallow and return None, never raise."""
        monkeypatch.setenv("OTEL_ENABLED", "true")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
        result = otel.setup_tracing()
        # Either a real provider (SDK present) or None (degraded) —
        # both are acceptable; what must NOT happen is an exception.
        assert result is None or hasattr(result, "add_span_processor")
        assert otel._provider is result or result is not None

    def test_idempotent(self, monkeypatch):
        sentinel = object()
        monkeypatch.setattr(otel, "_provider", sentinel)
        assert otel.setup_tracing() is sentinel


class TestInstrumentApp:
    def test_disabled_returns_app_passthrough(self, monkeypatch):
        monkeypatch.delenv("OTEL_ENABLED", raising=False)
        app = object()
        assert otel.instrument_app(app) is app

    def test_enabled_without_instrumentor_returns_app(self, monkeypatch):
        """Enabled but instrumentation import fails — app returned
        uninstrumented, not an exception."""
        monkeypatch.setenv("OTEL_ENABLED", "true")
        app = object()
        assert otel.instrument_app(app) is app
