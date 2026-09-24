"""Engine — domain, application use cases, ports and infrastructure.

Layer rule (enforced by tests/unit/architecture/test_import_boundaries):

    engine/  may NOT import: services.*, web.*, cli.*, flask,
             http.server, or anything transport-facing.

The Engine decides; the Backend (services/api_v1, landing, websocket)
transports and protects the boundary. Existing security/* and core/*
modules act as the Engine's current infrastructure — they are being
migrated under engine/infrastructure progressively, not moved in bulk.
"""
