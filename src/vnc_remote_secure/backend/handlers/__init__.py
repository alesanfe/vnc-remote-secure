"""Route handlers for ``/api/v1/*``, grouped by domain.

Each module owns one resource family; shared envelope/identity/body
plumbing lives in ``common``. ``services/api_v1.py`` keeps the
declarative ``_ROUTES`` registry and dispatch — handlers are pure
``handler -> response`` functions with no routing knowledge.
"""
