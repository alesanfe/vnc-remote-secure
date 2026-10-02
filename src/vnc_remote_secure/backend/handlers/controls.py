"""Operator controls: maintenance mode + gamepad kill-switch."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _err,
    _ok,
    _read_typed_body,
    _uc_error_status,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _get_maintenance(handler, query):
    try:
        from vnc_remote_secure.engine.application.maintenance import maintenance_status

        _ok(handler, maintenance_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /maintenance")
        _err(handler, "Maintenance state read failed", 500)


def _post_maintenance(handler, query):
    """POST /api/v1/maintenance — toggle maintenance mode
    (admin:* + step-up). Optional immediate/scheduled drain of
    existing share links."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import MaintenanceRequest

    body, error = _read_typed_body(handler, MaintenanceRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application.maintenance import set_maintenance
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        result = set_maintenance(
            operator.get("username", "unknown"),
            body.active,
            reason=body.reason,
            drain=body.drain,
            drain_timeout=body.drain_timeout,
        )
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))
        return
    _ok(handler, result)


def _gamepad_control(handler, stop: bool):
    """Local kill-switch — flips the shared ``gamepad:stopped`` flag
    the gamepad service checks per-connection and per-message, so the
    operator at the machine can cut remote input injection even while
    a session holds it."""
    from vnc_remote_secure.engine.infrastructure import stores

    try:
        stores.gamepad_set_stopped(stop)
    except Exception as e:  # noqa: BLE001
        _err(handler, str(e), 500)
        return
    from vnc_remote_secure.security.audit import audit_event

    audit_event(
        "portal_gamepad_" + ("stop" if stop else "resume"),
        user=(handler._api_operator or {}).get("username", "unknown"),
    )
    _ok(handler, {"gamepad_stopped": stop})


def _post_gamepad_stop(handler, query):
    _gamepad_control(handler, True)


def _post_gamepad_resume(handler, query):
    _gamepad_control(handler, False)
