"""Backend — transport boundary of the three-layer architecture.

    Frontend  →  presentation (React SPA, static bundle)
    Backend   →  HTTP/WebSocket transport: auth gate, CSRF, rate
                 limits, request schema validation, envelope
                 serialization, OpenAPI parity
    Engine    →  domain rules and use cases (engine/application)

This package is the *namespace* for backend concerns. Route handlers
live in ``backend/handlers/*`` grouped by domain; the declarative
``_ROUTES`` registry, rate limits and dispatch still live in
``services/api_v1.py`` (the landing process hosts the API) — the
registry is the contract, not the implementation.
``vnc_remote_secure.backend.api`` is the stable import path for the
versioned JSON API.

Boundary rules (enforced by tests/unit/architecture):

* Backend may import ``engine.application``/``engine.domain`` —
  never the reverse.
* Backend modules never import React/frontend code (the SPA is a
  static artifact, not a Python dependency).
* Handlers translate ``UseCaseError`` codes into HTTP status via the
  registry metadata; they do not re-implement domain rules.
"""
from __future__ import annotations
