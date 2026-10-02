"""Vulture whitelist — parameters kept for caller/API compatibility.

These names are *deliberately* unused inside their functions: they
exist because callers pass them (compat signatures) or a protocol
requires them. Listing them here keeps `debt_audit.py`'s dead-code
section at zero so every future finding is a real candidate.
"""

# backend/health_app.py + services/health.py: `ssl_context` is part of
# the public start/build signature — callers and tests pass it.
_.ssl_context  # noqa: F821

# core/doctor.py `run_doctor(as_json=...)` — documented API param.
_.as_json  # noqa: F821
