"""Landing page route handler for the web UI.

Serves the portal page linking to all available services.
"""
import os

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
)

from vnc_remote_secure.core.errors import error_json_response
from vnc_remote_secure.security.http_auth import check_landing_auth, client_ip_from

landing_bp = Blueprint('landing', __name__)


def _session_exchange(signed: str):
    """Exchange a signed share-link token for a session cookie.

    Mirrors ``services.landing._handle_session_exchange`` so the Flask
    landing implements the same share-link semantics as the
    ``http.server`` landing: a valid ``?session=<signed>`` URL
    activates the ephemeral session, burns single-use links without
    revoking the activated session, sets the ``vnc_ephemeral``
    HttpOnly cookie and redirects to ``/`` so the token leaves the
    URL (and Referer/history). Returns ``None`` when the link is
    invalid, expired, revoked, or exhausted.
    """
    from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
    # Forwarded-aware like check_session_permission — behind a trusted
    # proxy request.remote_addr is 127.0.0.1, so an allowed_ip-bound
    # session would never activate if we bound the raw peer.
    internal = activate_ephemeral_session(
        signed,
        client_ip=client_ip_from(request.headers, request.remote_addr))
    if not internal:
        return None
    resp = redirect('/')
    # X-Forwarded-Proto only counts behind a configured trusted proxy —
    # a direct client claiming https would receive a Secure cookie the
    # browser never returns over plain HTTP.
    trusted = os.environ.get(
        'TRUSTED_PROXY', 'false').lower() in ('true', '1', 'yes')
    secure = (request.is_secure
              or (trusted and
                  request.headers.get('X-Forwarded-Proto', '') == 'https'))
    from vnc_remote_secure.core.config import resolve_samesite
    resp.set_cookie('vnc_ephemeral', internal, httponly=True,
                    samesite=resolve_samesite(), secure=secure)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@landing_bp.route('/')
def index():
    """Render the landing page.

    Handles ``/?session=<signed>`` share links before normal auth —
    same behaviour as the ``http.server`` landing service.
    """
    signed = request.args.get('session', '')
    if signed:
        resp = _session_exchange(signed)
        if resp is not None:
            return resp
        body, status = error_json_response(
            'Session link is invalid, expired, or already used', 403)
        return body, status
    # Activated share-link session — same acceptance as the stdlib
    # landing: a valid vnc_ephemeral cookie grants portal access.
    eph = request.cookies.get('vnc_ephemeral', '')
    if eph:
        from vnc_remote_secure.security.ephemeral_sessions import check_session_permission
        if check_session_permission(
                eph, 'view',
                client_ip=client_ip_from(
                    request.headers, request.remote_addr)):
            config = current_app.config.get('VNC_CONFIG', {})
            template_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 'templates')
            index_path = os.path.join(template_dir, 'index.html')
            if os.path.exists(index_path):
                return render_template(
                    'index.html', config=config,
                    csrf_token=session.get('csrf_token', ''))
            return (
                '<!DOCTYPE html><html><head><title>VNC Remote Secure</title></head>'
                '<body><h1>VNC Remote Secure</h1>'
                '<p>Portal page.</p></body></html>'
            ), 200, {'Content-Type': 'text/html'}
    if not check_landing_auth(
            request.headers.get('Authorization', ''),
            client_ip=client_ip_from(
                request.headers, request.remote_addr)):
        body, status = error_json_response('Unauthorized', 401)
        resp = current_app.response_class(body, status=status)
        resp.headers['WWW-Authenticate'] = 'Basic realm="VNC Portal"'
        return resp
    config = current_app.config.get('VNC_CONFIG', {})
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    index_path = os.path.join(template_dir, 'index.html')
    if os.path.exists(index_path):
        return render_template(
            'index.html', config=config,
            csrf_token=session.get('csrf_token', ''))
    # Fallback minimal page.
    return (
        '<!DOCTYPE html><html><head><title>VNC Remote Secure</title></head>'
        '<body><h1>VNC Remote Secure</h1>'
        '<p>Portal page. Place templates/index.html for a custom UI.</p>'
        '</body></html>'
    ), 200, {'Content-Type': 'text/html'}
