"""Observability settings (pydantic-settings) + OTel opt-in gate."""
import pytest

pytestmark = pytest.mark.timeout(30)


def test_settings_defaults(monkeypatch):
    for var in ('OTEL_ENABLED', 'OTEL_EXPORTER_OTLP_ENDPOINT',
                'OTEL_SERVICE_NAME', 'LOG_JSON', 'LOG_LEVEL'):
        monkeypatch.delenv(var, raising=False)
    from vnc_remote_secure.monitoring.settings import load
    s = load()
    assert s.otel_enabled is False
    assert s.otel_exporter_otlp_endpoint is None
    assert s.log_level == 'INFO'


def test_settings_typed_env(monkeypatch):
    monkeypatch.setenv('OTEL_ENABLED', 'true')
    monkeypatch.setenv('OTEL_EXPORTER_OTLP_ENDPOINT',
                       'http://collector:4318')
    monkeypatch.setenv('LOG_LEVEL', 'debug')
    from vnc_remote_secure.monitoring.settings import load
    s = load()
    assert s.otel_enabled is True
    assert s.otel_exporter_otlp_endpoint == 'http://collector:4318'
    assert s.log_level == 'DEBUG'


def test_settings_rejects_bad_endpoint(monkeypatch):
    monkeypatch.setenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'notaurl')
    from vnc_remote_secure.monitoring.settings import load
    with pytest.raises(Exception):
        load()


def test_settings_rejects_bad_level(monkeypatch):
    monkeypatch.setenv('LOG_LEVEL', 'CHATTY')
    from vnc_remote_secure.monitoring.settings import load
    with pytest.raises(Exception):
        load()


def test_otel_disabled_by_default(monkeypatch):
    monkeypatch.delenv('OTEL_ENABLED', raising=False)
    from vnc_remote_secure.monitoring import otel
    assert otel.otel_enabled() is False


def test_session_cookie_expires(monkeypatch):
    """time-machine: a cookie must verify now and die after its
    lifetime without waiting for wall-clock time."""
    import time_machine
    monkeypatch.setenv('AUTH_SECRET', 'tm-test-secret-0123456789')
    from vnc_remote_secure.core.constants import (
        DEFAULT_SESSION_MAX_LIFETIME,
    )
    from vnc_remote_secure.security import sessions
    cookie = sessions.create_session_cookie('traveler')
    assert sessions.verify_session_cookie(cookie['value']) is not None
    import datetime as _dt
    with time_machine.travel(
            _dt.datetime.now() + _dt.timedelta(
                seconds=DEFAULT_SESSION_MAX_LIFETIME + 120)):
        assert sessions.verify_session_cookie(cookie['value']) is None
