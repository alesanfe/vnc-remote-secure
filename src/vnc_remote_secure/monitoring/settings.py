"""Typed observability settings (pydantic-settings).

This complements — never replaces — ``config.schema.json``: the schema
file stays the declarative contract operators validate with
``vnc-remote config validate``. This module is the runtime view for
the observability knobs (OTLP endpoint, service name, log format),
parsed once with types instead of scattered ``os.environ.get`` calls.
"""
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class TelemetrySettings(BaseSettings):
    """OTEL_* + LOG_* env surface, validated.

    ``OTEL_ENABLED`` off by default — telemetry export is strictly
    opt-in on a self-hosted security product.
    """
    model_config = SettingsConfigDict(extra='ignore', strict=True)

    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str | None = Field(
        default=None, max_length=512)
    otel_service_name: str = Field(default='', max_length=128)
    log_json: bool = False
    log_level: str = Field(default='INFO', max_length=16)

    @field_validator('log_level')
    @classmethod
    def _level_known(cls, v: str) -> str:
        v = v.strip().upper() or 'INFO'
        if v not in ('DEBUG', 'INFO', 'WARNING', 'WARN', 'ERROR',
                     'CRITICAL', 'FATAL'):
            raise ValueError(f'Unknown LOG_LEVEL: {v}')
        return v

    @field_validator('otel_exporter_otlp_endpoint')
    @classmethod
    def _endpoint_sane(cls, v):
        if v is None:
            return None
        from urllib.parse import urlparse
        try:
            p = urlparse(v)
        except ValueError:
            raise ValueError('unparseable OTLP endpoint')
        if p.scheme not in ('http', 'https') or not p.hostname:
            raise ValueError(
                'OTEL_EXPORTER_OTLP_ENDPOINT must be an http(s) URL')
        return v


def load() -> TelemetrySettings:
    """Parse the current environment (fresh each call — tests mutate
    env vars between cases and a cached settings object would leak)."""
    return TelemetrySettings()
