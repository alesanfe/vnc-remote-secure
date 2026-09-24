"""Stable facade for the versioned JSON API.

Consumers (``services/landing.py``, tests, future ASGI frontends)
should import from here, not from ``services.api_v1`` directly — the
module is free to be reorganized internally without breaking callers.
"""
from __future__ import annotations

from vnc_remote_secure.services.api_v1 import (
    _ROUTES,
    _csrf_token,
    _dispatch,
    _rate_limit,
    handle_get,
    handle_post,
    is_api_path,
)

__all__ = [
    'handle_get', 'handle_post', 'is_api_path',
    '_ROUTES', '_dispatch', '_rate_limit', '_csrf_token',
]
