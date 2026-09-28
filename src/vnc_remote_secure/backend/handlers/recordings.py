"""Desktop capture handlers — screenshot + session recordings.

MeshCentral parity: operators can snapshot the host framebuffer
(``GET /desktop/screenshot`` → PNG) and record the desktop to a
replayable ``.vrsrec`` stream (``/recordings*``). All routes are
``admin:*`` — recordings are forensic material.
"""
import logging

from vnc_remote_secure.backend.handlers.common import (
    _actor_name,
    _err,
    _ok,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _send_bytes(handler, data: bytes, content_type: str,
                filename: str | None = None) -> None:
    """Raw-bytes response — same pattern as /files/download."""
    handler.send_response(200)
    handler.send_header('Content-Type', content_type)
    if filename:
        safe = ''.join(
            c for c in filename if c.isalnum() or c in '._-')
        handler.send_header(
            'Content-Disposition', f'attachment; filename="{safe}"')
    handler.send_header('Content-Length', str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _get_screenshot(handler, query):
    """GET /desktop/screenshot — one PNG frame of the live desktop.

    Opens a short shared RFB connection, captures one full update and
    closes — it does not disturb connected viewers.
    """
    try:
        from vnc_remote_secure.engine.application import recordings
        png = recordings.screenshot(_actor_name(handler))
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /desktop/screenshot')
        _err(handler, 'Screenshot capture failed', 502)
        return
    _send_bytes(handler, png, 'image/png', 'screenshot.png')


def _get_recordings(handler, query):
    """GET /recordings — metadata list, newest first."""
    try:
        from vnc_remote_secure.engine.application import recordings
        _ok(handler, {'recordings': recordings.list_recordings()})
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /recordings')
        _err(handler, 'Recording listing failed', 500)


def _post_recordings(handler, query):
    """POST /recordings — spawn the background desktop recorder."""
    try:
        from vnc_remote_secure.engine.application import recordings
        _ok(handler, recordings.start(
            _actor_name(handler)), status=201)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /recordings POST')
        _err(handler, 'Recording start failed', 502)


def _recording_id(handler) -> str:
    return (getattr(handler, '_api_params', None) or {}).get('id', '')


def _get_recording(handler, query):
    """GET /recordings/{id} — the .vrsrec blob (player/download)."""
    try:
        from vnc_remote_secure.engine.application import recordings
        data, name = recordings.read(
            _recording_id(handler), _actor_name(handler))
    except FileNotFoundError:
        _err(handler, 'Recording not found', 404)
        return
    except ValueError as exc:
        _err(handler, str(exc), 400)
        return
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /recordings GET')
        _err(handler, 'Recording read failed', 500)
        return
    _send_bytes(handler, data, 'application/octet-stream', name)


def _post_recording_stop(handler, query):
    """POST /recordings/{id}/stop — finish a live recording."""
    try:
        from vnc_remote_secure.engine.application import recordings
        _ok(handler, recordings.stop(
            _recording_id(handler), _actor_name(handler)))
    except FileNotFoundError:
        _err(handler, 'Recording not running', 404)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /recordings stop')
        _err(handler, 'Recording stop failed', 500)


def _delete_recording(handler, query):
    """DELETE /recordings/{id} — remove a finished recording
    (step-up bound: forensic data destruction)."""
    try:
        from vnc_remote_secure.engine.application import recordings
        _ok(handler, recordings.delete(
            _recording_id(handler), _actor_name(handler)))
    except FileNotFoundError:
        _err(handler, 'Recording not found', 404)
    except RuntimeError as exc:
        _err(handler, str(exc), 409)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /recordings DELETE')
        _err(handler, 'Recording delete failed', 500)
