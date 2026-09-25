"""Landing portal service — launcher and portal-facing helpers.

The HTTP transport is FastAPI/uvicorn (``vnc_remote_secure.backend.app``).
This module keeps only what other services/tests legitimately need
from the portal process: lazy config access and the port/LAN/metrics
probes used by the status payload.
"""
import logging

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)


def _config():
    """Runtime config: loaded per call so test-time monkeypatching of
    env works (module-level snapshotting broke them)."""
    load_env_file()
    from vnc_remote_secure.core.config import get_config
    return get_config()


def check_port(port, host='127.0.0.1'):
    """Thin wrapper over ``core.portal.check_port`` — tests patch this
    name to fake service liveness."""
    from vnc_remote_secure.core.portal import check_port as _cp
    return _cp(port, host)


def get_lan_ips():
    """Local IPv4 addresses — portal display only."""
    from vnc_remote_secure.core.portal import get_lan_ips as _gi
    return _gi()


def get_system_metrics():
    """Host metrics for the portal page — best-effort."""
    from vnc_remote_secure.core.portal import get_system_metrics as _gm
    return _gm()


def _audio_capture_active() -> bool:
    """Return True while the audio service is capturing the mic."""
    try:
        from vnc_remote_secure.services.audio import audio_capture_active
        return audio_capture_active()
    except Exception:  # noqa: BLE001 - optional service absent
        return False


def main():
    """Start the landing portal server (FastAPI/uvicorn)."""
    from vnc_remote_secure.backend.app import main as _main
    _main()


if __name__ == '__main__':  # pragma: no cover
    main()
