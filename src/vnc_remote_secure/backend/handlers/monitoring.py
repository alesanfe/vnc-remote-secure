"""Read-model handlers: health, posture, doctor, audit, jobs ledger."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _err,
    _ok,
    _uc_err,
    audit_event_to_api,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _get_health(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, read_models.health())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /health")
        _err(handler, "Health status generation failed", 500)


def _get_posture(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, read_models.posture())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /security/posture")
        _err(handler, "Posture calculation failed", 500)


def _get_security_overview(handler, query):
    """GET /api/v1/security/overview — security-center rollup."""
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, read_models.security_overview())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /security/overview")
        _err(handler, "Security overview failed", 500)


def _get_doctor(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, read_models.doctor())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /doctor")
        _err(handler, "Doctor run failed", 500)


def _get_audit(handler, query):
    try:
        try:
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))
        # Cursor pagination: ``cursor`` is the seq of the last entry of
        # the previous page — opaque to the client, stable under
        # appends, no deep offsets.
        cursor = (query.get("cursor") or [None])[0]
        try:
            before_seq = int(cursor) if cursor else None
        except (TypeError, ValueError):
            _err(handler, "Invalid cursor", 400)
            return

        # Bounded, whitelisted filter params — raw query values are
        # length-capped so a huge ?user= can't burn CPU on matching.
        def _flt(name: str) -> str | None:
            v = (query.get(name) or [None])[0]
            if v is None:
                return None
            v = v.strip()[:128]
            return v or None

        from vnc_remote_secure.engine.application import read_models

        page = read_models.audit_page(
            limit,
            event=_flt("event"),
            before_seq=before_seq,
            user=_flt("user"),
            result=_flt("result"),
        )
        _ok(
            handler,
            {
                "entries": [audit_event_to_api(e) for e in page["entries"]],
                "next_cursor": page["next_cursor"],
                "has_more": page["has_more"],
            },
        )
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /audit")
        _err(handler, "Audit read failed", 500)


def _get_audit_verify(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, read_models.audit_integrity())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /audit/verify")
        _err(handler, "Audit verification failed", 500)


def _get_jobs(handler, query):
    """GET /api/v1/jobs — recent destructive-operation records."""
    try:
        limit = int((query.get("limit") or ["100"])[0])
    except ValueError:
        limit = 100
    try:
        from vnc_remote_secure.engine.application import read_models

        _ok(handler, {"jobs": read_models.jobs(limit)})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /jobs")
        _err(handler, "Job listing failed", 500)


def _get_job_detail(handler, query):
    """GET /api/v1/jobs/{jid} — one job record incl. progress phase."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.job_status(handler._api_params["jid"]))
    except UseCaseError as exc:
        _uc_err(handler, exc)
