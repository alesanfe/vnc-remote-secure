"""Desktop capture use cases — screenshot + session recordings.

MeshCentral parity surface: the operator console can snapshot the host
screen on demand and record the desktop to a replayable ``.vrsrec``
stream. All reachability/audit rules live here; the RFB wire work is
infrastructure (``stores`` → ``services/rfb_capture.py``).

Recordings are forensic-grade material (full screen content) so every
entry point is auditable and the store is the run dir — owner-only on
both POSIX and Windows ACLs.
"""
from __future__ import annotations

from vnc_remote_secure.engine.infrastructure import stores


def screenshot(actor: str) -> bytes:
    """PNG of the current host framebuffer. Audited as
    ``desktop_screenshot`` — a snapshot is an exfiltration event."""
    data = stores.desktop_screenshot()
    stores.audit('desktop_screenshot', actor, 'captured')
    return data


def list_recordings() -> list[dict]:
    return stores.recordings_list()


def start(actor: str) -> dict:
    """Begin a background desktop recording; returns {id, running}."""
    meta = stores.recording_start(actor)
    stores.audit('recording_start', actor, f'id={meta["id"]}')
    return meta


def stop(rec_id: str, actor: str) -> dict:
    """Stop a live recorder. 404-equivalent on unknown ids."""
    if not stores.recording_stop(rec_id):
        raise FileNotFoundError(rec_id)
    stores.audit('recording_stop', actor, f'id={rec_id}')
    return {'id': rec_id, 'running': False}


def read(rec_id: str, actor: str) -> tuple[bytes, str]:
    """Full .vrsrec blob for the in-app player / download."""
    data, name = stores.recording_read(rec_id)
    stores.audit('recording_download', actor, f'id={rec_id}')
    return data, name


def delete(rec_id: str, actor: str, auth_ctx=None) -> dict:
    # Catalog: recording.delete is 'stepup-bound' — the grant must be
    # consumed here (single-use, bound to this recording id), not just
    # the route's recency check. CLI calls (no auth_ctx) skip it — the
    # shell is the auth boundary there.
    from vnc_remote_secure.engine.application.ops import (
        require_bound_step_up,
    )
    require_bound_step_up(actor, 'recording.delete', rec_id, auth_ctx)
    if not stores.recording_delete(rec_id):
        raise FileNotFoundError(rec_id)
    stores.audit('recording_delete', actor, f'id={rec_id}')
    return {'deleted': rec_id}
