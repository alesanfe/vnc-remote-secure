"""CLI-parity operation handlers: version, lifecycle, backups, secrets, config, upgrade."""

import logging

from vnc_remote_secure.backend.handlers.common import (
    _auth_ctx,
    _err,
    _ok,
    _read_typed_body,
    _uc_err,
    _uc_error_status,
    backup_to_api,
    config_entry_to_api,
)
from vnc_remote_secure.core.errors import log_exception

logger = logging.getLogger(__name__)


def _get_version(handler, query):
    """GET /api/v1/version — installed package version."""
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.version())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /version")
        _err(handler, "Version read failed", 500)


def _get_lifecycle(handler, query):
    """GET /api/v1/lifecycle — PID/running map + port health
    (``vnc-remote status`` parity)."""
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.lifecycle_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /lifecycle")
        _err(handler, "Service status read failed", 500)


def _post_lifecycle(handler, query):
    """POST /api/v1/lifecycle — {action: start|stop|restart}.

    Spawns the detached deferred runner: the portal answers the
    request, then the child runs the action — so ``stop``/``restart``
    can kill the portal service itself without losing the response.
    """
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import LifecycleRequest

    body, error = _read_typed_body(handler, LifecycleRequest, limit=1024)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        result = ops.lifecycle_action(
            operator.get("username", "?"), body.action, _auth_ctx(handler)
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)
        return
    _ok(handler, result, status=202)


def _get_backups(handler, query):
    try:
        from vnc_remote_secure.engine.application import read_models

        items = []
        for path in read_models.backup_paths():
            import os

            try:
                items.append(backup_to_api(path, os.stat(path)))
            except OSError:
                continue
        _ok(handler, {"backups": items})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /backups")
        _err(handler, "Backup listing failed", 500)


def _post_backup_create(handler, query):
    """POST /api/v1/backups — create a backup archive."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.create_backup(operator.get("username", "?"), _auth_ctx(handler)),
            status=201,
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _post_backup_verify(handler, query):
    """POST /api/v1/backups/verify — {file} CRC/decrypt check."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import BackupFileRequest

    body, error = _read_typed_body(handler, BackupFileRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.verify_backup(operator.get("username", "?"), body.file))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_backup_restore(handler, query):
    """POST /api/v1/backups/restore — {file} overwrites live config."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import BackupFileRequest

    body, error = _read_typed_body(handler, BackupFileRequest, limit=4096)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.restore_backup(operator.get("username", "?"), body.file, _auth_ctx(handler)),
            status=202,
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _get_secrets(handler, query):
    """GET /api/v1/secrets — per-secret status, never values."""
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.secrets_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /secrets")
        _err(handler, "Secret status read failed", 500)


def _get_secret_redact(handler, query):
    """GET /api/v1/secrets/{name} — fingerprinted redaction."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.secret_redact(handler._api_params["name"]))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_secret_rotate(handler, query):
    """POST /api/v1/secrets/{name}/rotate — hard cutover rotation."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.rotate_secret(
                operator.get("username", "?"), handler._api_params["name"], _auth_ctx(handler)
            ),
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _post_secrets_rotate_signing(handler, query):
    """POST /api/v1/secrets/rotate-signing — coexistence window."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.rotate_signing_key(operator.get("username", "?"), _auth_ctx(handler)))
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _post_secrets_check(handler, query):
    """POST /api/v1/secrets/check — {fix?} TLS + permission findings.
    An empty body means check-only."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import SecretsCheckRequest

    fix = False
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except (TypeError, ValueError):
        length = 0
    if length:
        body, error = _read_typed_body(handler, SecretsCheckRequest, limit=1024)
        if error:
            _err(handler, *error)
            return
        fix = body.fix
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.secrets_check(operator.get("username", "?"), fix=fix))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_recovery_codes(handler, query):
    """POST /api/v1/secrets/recovery-codes — the plaintext codes are
    returned ONCE in the response; only hashes persist."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.recovery_codes(operator.get("username", "?"), _auth_ctx(handler)))
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _get_config_effective(handler, query):
    """GET /api/v1/config/effective?profile= — full provenance table."""
    profile = (query.get("profile") or [None])[0]
    try:
        from vnc_remote_secure.engine.infrastructure import stores

        entries = stores.config_effective_profile(profile or None)
        _ok(handler, {"profile": profile, "vars": [config_entry_to_api(e) for e in entries]})
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /config/effective")
        _err(handler, "Config inspection failed", 500)


def _get_config_explain(handler, query):
    """GET /api/v1/config/explain/{name} — one variable's provenance."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        result = ops.config_explain(handler._api_params["name"])
        _ok(handler, {"entry": config_entry_to_api(result["entry"])})
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _get_config_validate(handler, query):
    """GET /api/v1/config/validate?profile= — contradiction findings."""
    profile = (query.get("profile") or [None])[0]
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.config_validate(profile or None))
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /config/validate")
        _err(handler, "Config validation failed", 500)


def _get_config_diff(handler, query):
    """GET /api/v1/config/diff?a=..&b=.. — profile diff."""
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(handler, ops.config_diff((query.get("a") or [""])[0], (query.get("b") or [""])[0]))
    except UseCaseError as exc:
        _err(handler, exc.detail or exc.code, _uc_error_status(exc))


def _post_config_migrate(handler, query):
    """POST /api/v1/config/migrate — {dry_run?} legacy .env renames.
    An empty body defaults to a real (non-dry-run) apply."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import ConfigMigrateRequest

    dry_run = False
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except (TypeError, ValueError):
        length = 0
    if length:
        body, error = _read_typed_body(handler, ConfigMigrateRequest, limit=1024)
        if error:
            _err(handler, *error)
            return
        dry_run = body.dry_run
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.config_migrate(
                operator.get("username", "?"), dry_run=dry_run, auth_ctx=_auth_ctx(handler)
            ),
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _get_config_history(handler, query):
    """GET /api/v1/config/history — env snapshots (metadata only)."""
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.config_history())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /config/history")
        _err(handler, "Config history read failed", 500)


def _post_config_rollback(handler, query):
    """POST /api/v1/config/rollback — {snapshot} restores .env."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import ConfigRollbackRequest

    body, error = _read_typed_body(handler, ConfigRollbackRequest, limit=1024)
    if error:
        _err(handler, *error)
        return
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.config_rollback(
                operator.get("username", "?"),
                body.snapshot,
                restart=body.restart,
                auth_ctx=_auth_ctx(handler),
            ),
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _get_upgrade(handler, query):
    """GET /api/v1/upgrade — installed vs available version."""
    try:
        from vnc_remote_secure.engine.application import ops

        _ok(handler, ops.upgrade_status())
    except Exception as e:  # noqa: BLE001
        log_exception(e, "api /upgrade")
        _err(handler, "Upgrade check failed", 500)


def _post_upgrade(handler, query):
    """POST /api/v1/upgrade — {source?} self-upgrade w/ rollback."""
    operator = handler._api_operator
    from vnc_remote_secure.backend.schemas import UpgradeRequest

    source = None
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except (TypeError, ValueError):
        length = 0
    if length:
        body, error = _read_typed_body(handler, UpgradeRequest, limit=4096)
        if error:
            _err(handler, *error)
            return
        source = body.source
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.upgrade_run(
                operator.get("username", "?"), source=source, auth_ctx=_auth_ctx(handler)
            ),
            status=202,
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)


def _post_upgrade_rollback(handler, query):
    """POST /api/v1/upgrade/rollback — restore pre-upgrade snapshot."""
    operator = handler._api_operator
    from vnc_remote_secure.engine.application import ops
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        _ok(
            handler,
            ops.upgrade_rollback(operator.get("username", "?"), _auth_ctx(handler)),
            status=202,
        )
    except UseCaseError as exc:
        _uc_err(handler, exc)
