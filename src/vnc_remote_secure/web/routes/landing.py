"""Landing page route handler for the web UI.

Serves the portal page linking to all available services.
"""
import os

from flask import Blueprint, current_app, render_template, send_from_directory

landing_bp = Blueprint('landing', __name__)


@landing_bp.route('/')
def index():
    """Render the landing page.

    When templates are available (``templates/index.html``) they are
    rendered with the current configuration; otherwise a minimal HTML
    page is returned.
    """
    config = current_app.config.get('VNC_CONFIG', {})
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    index_path = os.path.join(template_dir, 'index.html')
    if os.path.exists(index_path):
        return render_template('index.html', config=config)
    # Fallback minimal page.
    return (
        '<!DOCTYPE html><html><head><title>VNC Remote Secure</title></head>'
        '<body><h1>VNC Remote Secure</h1>'
        '<p>Portal page. Place templates/index.html for a custom UI.</p>'
        '</body></html>'
    ), 200, {'Content-Type': 'text/html'}


@landing_bp.route('/static/<path:filename>')
def static_files(filename):
    """Serve static assets from the web templates directory."""
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')
    return send_from_directory(static_dir, filename)
