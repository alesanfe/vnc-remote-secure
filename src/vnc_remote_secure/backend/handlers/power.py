"""Host power handlers: shutdown/restart/sleep + Wake-on-LAN."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _auth_ctx,
    _err,
    _ok,
    _read_json_body,
    _uc_err,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _post_power(handler, query):
    """POST /api/v1/power — shutdown/restart/sleep the host.

    admin:* + step-up (route flag). The use case runs the action on a
    grace delay so this 200 is delivered before the host drops."""
    operator = handler._api_operator
    body, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    action = str(body.get("action") or "").strip()
    try:
        from vnc_remote_secure.engine.application.power import host_power
        from vnc_remote_secure.engine.domain.decision import UseCaseError

        try:
            _ok(handler, host_power(action, operator.get("username", "?"), _auth_ctx(handler)))
        except UseCaseError as exc:
            _uc_err(handler, exc)
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /power")
        _err(handler, "Power action failed", 500)


def _post_power_wol(handler, query):
    """POST /api/v1/power/wol — Wake-on-LAN magic packet."""
    operator = handler._api_operator
    body, error = _read_json_body(handler)
    if error:
        _err(handler, *error)
        return
    mac = str(body.get("mac") or "")
    broadcast = str(body.get("broadcast") or "255.255.255.255")
    try:
        port = int(body.get("port") or 9)
    except (TypeError, ValueError):
        _err(handler, "invalid port", 400)
        return
    try:
        from vnc_remote_secure.engine.application.power import wake_on_lan

        _ok(handler, wake_on_lan(mac, broadcast, port, actor=operator.get("username", "?")))
    except ValueError as exc:
        _err(handler, str(exc), 400)
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /power/wol")
        _err(handler, "Wake-on-LAN failed", 500)
