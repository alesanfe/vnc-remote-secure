"""Public share-link URL derivation — shared by the CLI and the API.

The link lands on the portal; scheme+port come from the effective
deployment: nginx+TLS fronts everything on HTTPS; without nginx the
landing page itself is the entry point (HTTP on LANDING_PORT).

``PUBLIC_BASE_URL`` (e.g. ``https://vnc.mydomain.org``) overrides the
derivation entirely — needed when the public host is not derivable
from ``DUCK_DOMAIN`` (a subdomain deployment, a custom domain, a VPN
alias) and for the CLI, which has no request headers to learn it from.

This is a pure read of configuration — both Backend (session-create
response) and CLI (`session create` output) consume it, so it lives
in ``core`` rather than inside either caller.
"""

from __future__ import annotations

import os

from vnc_remote_secure.core.config import env_flag


def share_base_url() -> str:
    """Derive the public base URL for a share link."""
    from vnc_remote_secure.core.constants import (
        DEFAULT_LANDING_PORT,
        DEFAULT_NGINX_HTTPS_PORT,
    )

    explicit = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if explicit.startswith(("https://", "http://")):
        return explicit

    # Bare 'mysub' needs the .duckdns.org suffix to form a working
    # hostname — same normalization nginx server_name applies.
    try:
        from vnc_remote_secure.core.config import normalize_duck_domain

        host = normalize_duck_domain(os.environ.get("DUCK_DOMAIN", "")) or "127.0.0.1"
    except ImportError:
        host = os.environ.get("DUCK_DOMAIN", "").strip() or "127.0.0.1"
    nginx_on = env_flag("NGINX_ENABLED", "false")
    if nginx_on:
        # nginx terminates TLS and fronts every service on 443 — the
        # public URL is always HTTPS regardless of the loopback
        # backends' own TLS_ENABLED (which only governs the direct
        # listeners nginx proxies to).
        https_port = os.environ.get("NGINX_HTTPS_PORT", str(DEFAULT_NGINX_HTTPS_PORT))
        return (
            f"https://{host}"
            if https_port == str(DEFAULT_NGINX_HTTPS_PORT)
            else f"https://{host}:{https_port}"
        )
    # No nginx: the landing page itself is the public entry point, so
    # its own TLS resolution decides the scheme. TLS_ENABLED/DISABLE_SSL
    # unification lives in config._is_tls_enabled() — a raw env read
    # here would ignore DISABLE_SSL and the default-true.
    try:
        from vnc_remote_secure.core.config import get_config

        tls_flag = bool(get_config().get("tls_enabled")) or bool(os.environ.get("SSL_CERT"))
    except Exception:  # noqa: BLE001 - fall back to raw env
        _disabled = env_flag("DISABLE_SSL", "")
        tls_flag = (not _disabled) and (
            env_flag("TLS_ENABLED", "false") or bool(os.environ.get("SSL_CERT"))
        )
    # TLS resolution must use the real context builder (env certs
    # or canonical ssl-dir discovery) — not the env flag alone —
    # so a deployment whose certs resolve via the ssl dir does not
    # get an http:// link.
    try:
        from vnc_remote_secure.security.certificates import create_ssl_context

        tls_on = create_ssl_context() is not None
    except Exception:  # noqa: BLE001 - fall back to env flag
        tls_on = tls_flag
    landing_port = os.environ.get("LANDING_PORT", str(DEFAULT_LANDING_PORT))
    scheme = "https" if tls_on else "http"
    return f"{scheme}://{host}:{landing_port}"
