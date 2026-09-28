"""File-share handlers: list, download, upload, mkdir."""
import base64
import logging

from vnc_remote_secure.backend.handlers.common import (
    _actor_name,
    _ephemeral_session,
    _err,
    _ok,
    _read_json_body,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _files_allowed(handler) -> bool:
    """file_transfer gate for 'session'-perm routes.

    Operators get the host file share outright; an ephemeral session
    must explicitly carry ``file_transfer`` AND either be unbound or
    bound to the 'files' resource — a desktop-scoped link must not
    reach the filesystem as a side channel.
    """
    if getattr(handler, '_api_operator', None) is not None:
        return True
    session = _ephemeral_session(handler)
    if session is None:
        _err(handler, 'Not found', 404)
        return False
    bound = getattr(session, 'resource', None)
    if bound not in (None, 'files'):
        _err(handler, 'Not found', 404)
        return False
    if not session.has_permission('file_transfer', resource='files'):
        _err(handler, 'file_transfer permission required', 403)
        return False
    return True


def _get_files(handler, query):
    """GET /files?path= — list one directory inside the share root."""
    if not _files_allowed(handler):
        return
    from vnc_remote_secure.engine.application import files
    rel = (query.get('path') or [''])[0]
    try:
        data = files.list_dir(rel, _actor_name(handler))
        data.update(files.share_info())
        _ok(handler, data)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /files')
        _err(handler, 'File listing failed', 500)


def _get_files_download(handler, query):
    """GET /files/download?path= — raw bytes, attachment disposition."""
    if not _files_allowed(handler):
        return
    from vnc_remote_secure.engine.application import files
    rel = (query.get('path') or [''])[0]
    try:
        data, name = files.read_file(rel, _actor_name(handler))
    except ValueError as exc:
        _err(handler, str(exc), 400)
        return
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /files/download')
        _err(handler, 'Download failed', 500)
        return
    safe_name = ''.join(
        c for c in name if c.isalnum() or c in '._- ') or 'download'
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/octet-stream')
    handler.send_header(
        'Content-Disposition', f'attachment; filename="{safe_name}"')
    handler.send_header('Content-Length', str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _post_files_upload(handler, query):
    """POST /files/upload — {path, content_b64, overwrite?}.

    JSON+base64 keeps this inside the existing typed-body pipeline
    (the API surface is JSON-only; multipart would need a parser).
    """
    if not _files_allowed(handler):
        return
    from vnc_remote_secure.engine.application import files
    body, error = _read_json_body(
        handler, limit=int(files.MAX_FILE_BYTES * 4 / 3) + 4096)
    if error:
        _err(handler, *error)
        return
    import binascii
    rel = str(body.get('path') or '')
    try:
        data = base64.b64decode(
            str(body.get('content_b64') or ''), validate=True)
    except (binascii.Error, ValueError):
        _err(handler, 'content_b64 must be base64', 400)
        return
    try:
        _ok(handler, files.write_file(
            rel, data, _actor_name(handler),
            overwrite=bool(body.get('overwrite'))), status=201)
    except FileExistsError:
        _err(handler, 'File already exists', 409)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /files/upload')
        _err(handler, 'Upload failed', 500)


def _post_files_mkdir(handler, query):
    """POST /files/mkdir — {path} creates one directory."""
    if not _files_allowed(handler):
        return
    body, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import files
    try:
        _ok(handler, files.mkdir(
            str(body.get('path') or ''), _actor_name(handler)),
            status=201)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, 'api /files/mkdir')
        _err(handler, 'mkdir failed', 500)
