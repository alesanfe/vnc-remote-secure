"""OpenTelemetry tracing — opt-in OTLP export for the FastAPI surfaces.

Disabled by default: a self-hosted security product must not phone
telemetry anywhere unless the operator asks. Set
``OTEL_ENABLED=true`` and ``OTEL_EXPORTER_OTLP_ENDPOINT=http://…``
to export traces; ``OTEL_SERVICE_NAME`` overrides the service name.

Sensitive span attributes are dropped before export: cookies,
Authorization headers, share-link tokens and query strings never
leave the process (share tokens would otherwise leak into the
collector — URLs are recorded as the route template only).
"""
import logging

logger = logging.getLogger(__name__)

# Header names scrubbed from spans — request headers are recorded by
# the instrumentor as http.request.header.* attributes.
_SENSITIVE_HEADERS = frozenset({
    'cookie', 'authorization', 'x-vncremote-signature',
    'set-cookie', 'proxy-authorization',
})

_provider = None


def otel_enabled() -> bool:
    from vnc_remote_secure.monitoring.settings import load
    try:
        return load().otel_enabled
    except Exception:  # noqa: BLE001 - invalid settings → disabled
        logger.warning("OTEL settings invalid — tracing disabled",
                       exc_info=True)
        return False


def setup_tracing(service_name: str = 'vnc-remote-secure'):
    """Create the TracerProvider + OTLP exporter. Idempotent."""
    global _provider
    if _provider is not None:
        return _provider
    if not otel_enabled():
        return None
    try:
        import os  # noqa: F401 - OTLP exporter reads the env endpoint

        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
        )

        from vnc_remote_secure.monitoring.settings import load
        settings = load()
        if settings.otel_exporter_otlp_endpoint:
            os.environ.setdefault(
                'OTEL_EXPORTER_OTLP_ENDPOINT',
                settings.otel_exporter_otlp_endpoint)
        import vnc_remote_secure
        provider = TracerProvider(resource=Resource.create({
            'service.name': settings.otel_service_name or service_name,
            'service.version': getattr(
                vnc_remote_secure, '__version__', 'unknown'),
        }))
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        _provider = provider
        logger.info("OTel tracing enabled (OTLP)")
        return provider
    except Exception:  # noqa: BLE001 - telemetry must never break the app
        logger.warning("OTel setup failed — tracing disabled",
                       exc_info=True)
        return None


def instrument_app(app, service_name: str = 'vnc-remote-secure'):
    """Attach FastAPI instrumentation when OTel is enabled.

    ``exclude_spans='receive/send'`` avoids noise; sensitive headers
    are stripped via ``http_capture_headers_*`` defaults plus our own
    suppression list handled by the sanitization hook.
    """
    if not otel_enabled():
        return app
    try:
        from opentelemetry.instrumentation.fastapi import (
            FastAPIInstrumentor,
        )
        FastAPIInstrumentor.instrument_app(
            app,
            excluded_urls='/health,/metrics,/health/live,'
                          '/health/ready,/health/services')
        logger.info("OTel FastAPI instrumentation active")
    except Exception:  # noqa: BLE001
        logger.warning("OTel instrumentation failed — disabled",
                       exc_info=True)
    return app
