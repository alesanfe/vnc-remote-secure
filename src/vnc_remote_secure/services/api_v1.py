"""Versioned JSON API for the admin SPA (``/api/v1/*``).

Served by the landing handler. The portal-level auth gate has already
run for GETs (ephemeral cookie or operator Basic-auth); operator-only
routes additionally require ``handler._portal_operator`` — an
ephemeral share-link session is never an operator. Mutating routes
go through ``handler._operator_gate`` which re-authenticates the
Basic credential and enforces Origin + Sec-Fetch-Site CSRF checks.

Success responses use the ``{data, error, request_id}`` envelope;
errors reuse the canonical ``error_json`` body via ``send_json_error``.

This module is the contract layer: the ``_ROUTES`` registry, rate
limits and the dispatch machinery. Route handlers live in
``vnc_remote_secure.backend.handlers.*`` grouped by domain; shared
envelope/identity plumbing lives in ``backend.handlers.common``.
"""
import logging
import time

from vnc_remote_secure.backend.handlers.auth import (
    _get_auth_methods,
    _post_auth_login,
    _post_auth_passkey_begin,
    _post_auth_passkey_complete,
    _post_logout,
    _post_step_up,
)
from vnc_remote_secure.backend.handlers.chat import (
    _get_chat,
    _post_chat,
)
from vnc_remote_secure.backend.handlers.common import (
    _err,
    _operator,
)
from vnc_remote_secure.backend.handlers.controls import (
    _get_maintenance,
    _post_gamepad_resume,
    _post_gamepad_stop,
    _post_maintenance,
)
from vnc_remote_secure.backend.handlers.files import (
    _get_files,
    _get_files_download,
    _post_files_mkdir,
    _post_files_upload,
)
from vnc_remote_secure.backend.handlers.monitoring import (
    _get_audit,
    _get_audit_verify,
    _get_doctor,
    _get_health,
    _get_job_detail,
    _get_jobs,
    _get_posture,
)
from vnc_remote_secure.backend.handlers.operators import (
    _delete_operator,
    _delete_passkey,
    _get_operator_detail,
    _get_operator_passkeys,
    _get_operators,
    _get_operators_deleted,
    _patch_operator,
    _patch_passkey,
    _post_operator_create,
    _post_operator_restore,
    _post_operator_revoke_sessions,
    _post_passkey_register_begin,
    _post_passkey_register_complete,
)
from vnc_remote_secure.backend.handlers.ops import (
    _get_backups,
    _get_config,
    _get_config_diff,
    _get_config_effective,
    _get_config_explain,
    _get_config_validate,
    _get_lifecycle,
    _get_secret_redact,
    _get_secrets,
    _get_upgrade,
    _get_version,
    _post_backup_create,
    _post_backup_restore,
    _post_backup_verify,
    _post_config_migrate,
    _post_lifecycle,
    _post_recovery_codes,
    _post_secret_rotate,
    _post_secrets_check,
    _post_secrets_rotate_signing,
    _post_upgrade,
    _post_upgrade_rollback,
)
from vnc_remote_secure.backend.handlers.portal import (
    _get_me,
    _get_portal,
    _get_services,
    _get_session_context,
    _get_status,
    _post_session_activate,
    _post_session_preview,
)
from vnc_remote_secure.backend.handlers.power import (
    _post_power,
    _post_power_wol,
)
from vnc_remote_secure.backend.handlers.recordings import (
    _delete_recording,
    _get_recording,
    _get_recordings,
    _get_screenshot,
    _post_recording_stop,
    _post_recordings,
)
from vnc_remote_secure.backend.handlers.sessions import (
    _get_session_detail,
    _get_sessions,
    _post_session_create,
    _post_session_revoke,
    _post_session_revoke_all,
)
from vnc_remote_secure.backend.handlers.system_users import (
    _delete_system_user,
    _get_system_users,
    _post_system_user_create,
)

logger = logging.getLogger(__name__)

_API_PREFIX = '/api/v1/'

# Per-scope rate limits: (max requests, window seconds). These sit on
# top of the auth layer — expensive endpoints (doctor, audit verify)
# get tight budgets so the API cannot be used to burn CPU/disk.
_RATE_LIMITS = {
    'sessions.create': (30, 60),
    'sessions.revoke': (60, 60),
    'sessions.revoke-all': (10, 60),
    'doctor': (6, 60),
    'audit': (60, 60),
    'audit.verify': (10, 60),
    'session.activate': (30, 60),
    'session.preview': (60, 60),
    # Operator management — destructive scopes get tighter budgets.
    'operators.create': (10, 60),
    'operators.update': (30, 60),
    'operators.delete': (10, 60),
    'operators.sessions_revoke': (30, 60),
    'passkeys.register': (10, 60),
    'passkeys.manage': (30, 60),
    'system_users.manage': (30, 60),
    'maintenance': (10, 60),
    # Operations parity — destructive/host-level actions get the
    # tightest budgets.
    'lifecycle': (6, 60),
    'backups.write': (10, 60),
    'secrets.rotate': (10, 60),
    'config.write': (10, 60),
    'upgrade': (6, 60),
    # Credential oracles — throttled as hard as the login limiter.
    'login': (10, 60),
    'passkeys.auth': (10, 60),
    # Step-up re-authentication — a password-verification oracle must
    # be throttled as hard as login itself.
    'stepup': (10, 60),
    # File share + chat — writes are tighter than reads; downloads
    # bounded so a guest can't hammer the disk.
    'files.list': (60, 60),
    'files.download': (60, 60),
    'files.write': (20, 60),
    'chat': (120, 60),
    # Host power — shutdown/restart/sleep/WoL. A flood of these is a
    # denial of service on the host itself.
    'power': (4, 60),
    'default': (120, 60),
}
_RATE_NS = 'api_rate'


def _rate_limit(handler, scope: str) -> bool:
    """Fixed-window per-IP-per-scope limiter over the shared backend.

    Fails closed on backend errors for mutating scopes and open for
    reads — a redis/sqlite hiccup must not blind the operator, but a
    mutation flood must not sail through either.
    """
    from vnc_remote_secure.security.http_auth import client_ip_from
    ip = client_ip_from(handler.headers, handler.peer_ip()) or 'unknown'
    max_req, window = _RATE_LIMITS.get(scope, _RATE_LIMITS['default'])
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        bucket = int(time.time() // window)
        count = get_backend().increment(
            _RATE_NS, f'{scope}\x00{ip}\x00{bucket}', 1, window)
        allowed = int(count) <= max_req
    except Exception:  # noqa: BLE001 - degraded, not silent
        logger.warning('API rate limiter unavailable (scope=%s)', scope)
        allowed = scope not in ('sessions.create', 'sessions.revoke',
                                'sessions.revoke-all')
    if not allowed:
        _err(handler, 'Too many requests', 429)
    return allowed


def is_api_path(path: str) -> bool:
    """Return True when ``path`` is an /api/v1/* route."""
    return path.startswith(_API_PREFIX)



# ---------------------------------------------------------------------------
# Declarative route registry
# ---------------------------------------------------------------------------
# Single source of truth for the API contract. ``perm`` is the
# operator capability required (``None`` = any authenticated portal
# user, including ephemeral share-link sessions; the literal
# 'operator' = operator account, no specific capability). ``scope``
# selects the rate-limit budget; ``audit`` names the event a mutation
# must emit; ``resp`` names the public response schema the handler
# serializes through — declared here so a contract test can flag a
# mutation that forgets either.
from collections import namedtuple

# ``step_up`` — a mutation additionally requires a *recent*
# authentication (POST /api/v1/step-up grants 5 minutes): mass
# revocation and operator lifecycle changes are gated on it.
_Route = namedtuple(
    '_Route', 'fn perm scope audit resp step_up', defaults=[False])

_ROUTES = {
    ('GET', 'me'): _Route(
        _get_me, None, 'default', None, 'MeResponse'),
    ('GET', 'portal'): _Route(
        _get_portal, 'session', 'default', None, 'PortalResponse'),
    ('GET', 'status'): _Route(
        _get_status, None, 'default', None, 'StatusResponse'),
    ('GET', 'session-context'): _Route(
        _get_session_context, None, 'default', None,
        'SessionContextResponse'),
    ('GET', 'services'): _Route(
        _get_services, 'operator', 'default', None, 'ServicesResponse'),
    ('GET', 'sessions'): _Route(
        _get_sessions, 'admin_sessions', 'default', None,
        'SessionPageResponse'),
    ('GET', 'sessions/{token_id}'): _Route(
        _get_session_detail, 'admin_sessions', 'default', None,
        'SessionDetailResponse'),
    # File share — 'session' perm so guests with file_transfer can
    # use it; the handlers gate the capability per-identity.
    ('GET', 'files'): _Route(
        _get_files, 'session', 'files.list', None, 'FileListResponse'),
    ('GET', 'files/download'): _Route(
        _get_files_download, 'session', 'files.download', None,
        'FileDownloadResponse'),
    ('POST', 'files/upload'): _Route(
        _post_files_upload, 'session', 'files.write',
        'file_transfer_upload', 'FileWriteResponse'),
    ('POST', 'files/mkdir'): _Route(
        _post_files_mkdir, 'session', 'files.write',
        'file_transfer_mkdir', 'FileWriteResponse'),
    # Session-scoped chat — both parties reach the same channel.
    ('GET', 'chat'): _Route(
        _get_chat, 'session', 'chat', None, 'ChatResponse'),
    ('POST', 'chat'): _Route(
        _post_chat, 'session', 'chat', 'session_chat_message',
        'ChatPostResponse'),
    ('GET', 'health'): _Route(
        _get_health, 'operator', 'default', None, 'HealthResponse'),
    ('GET', 'security/posture'): _Route(
        _get_posture, 'operator', 'default', None, 'PostureResponse'),
    ('GET', 'doctor'): _Route(
        _get_doctor, 'operator', 'doctor', None, 'DoctorResponse'),
    ('GET', 'audit'): _Route(
        _get_audit, 'admin_audit', 'audit', None, 'AuditPageResponse'),
    ('GET', 'audit/verify'): _Route(
        _get_audit_verify, 'admin_audit', 'audit.verify', None,
        'AuditVerifyResponse'),
    ('GET', 'config'): _Route(
        _get_config, 'admin_config', 'default', None,
        'ConfigPageResponse'),
    ('GET', 'backups'): _Route(
        _get_backups, 'operator', 'default', None,
        'BackupPageResponse'),
    ('GET', 'operators'): _Route(
        _get_operators, 'admin_users', 'default', None,
        'OperatorPageResponse'),
    ('GET', 'maintenance'): _Route(
        _get_maintenance, 'operator', 'default', None,
        'MaintenanceResponse'),
    # Public auth surface — the SPA login page consumes these before
    # any session exists. 'public' skips _operator_gate; handlers run
    # _public_gate (Origin + Sec-Fetch) instead.
    ('GET', 'auth/methods'): _Route(
        _get_auth_methods, 'public', 'default', None,
        'AuthMethodsResponse'),
    ('POST', 'auth/login'): _Route(
        _post_auth_login, 'public', 'login', 'operator_login',
        'LoginResponse'),
    ('POST', 'auth/passkey/begin'): _Route(
        _post_auth_passkey_begin, 'public', 'passkeys.auth',
        'passkey_auth_begin', 'PasskeyAuthOptionsResponse'),
    ('POST', 'auth/passkey/complete'): _Route(
        _post_auth_passkey_complete, 'public', 'passkeys.auth',
        'operator_login', 'LoginResponse'),
    # Share-link exchange — public: the token IS the credential and
    # travels in the request body, never in a URL.
    ('POST', 'session/preview'): _Route(
        _post_session_preview, 'public', 'session.preview',
        'session_preview', 'SessionPreviewResponse'),
    ('POST', 'session/activate'): _Route(
        _post_session_activate, 'public', 'session.activate',
        'ephemeral_session_activate', 'SessionActivateResponse'),
    # Local gamepad kill-switch (operator-only — the flag cuts remote
    # input injection even while a share session holds it).
    ('POST', 'gamepad/stop'): _Route(
        _post_gamepad_stop, 'admin_sessions', 'default',
        'portal_gamepad_stop', 'GamepadStateResponse'),
    ('POST', 'gamepad/resume'): _Route(
        _post_gamepad_resume, 'admin_sessions', 'default',
        'portal_gamepad_resume', 'GamepadStateResponse'),
    ('POST', 'maintenance'): _Route(
        _post_maintenance, 'admin:*', 'maintenance',
        'maintenance_changed', 'MaintenanceSetResponse', True),
    ('POST', 'sessions'): _Route(
        _post_session_create, 'admin_sessions', 'sessions.create',
        'ephemeral_session_create', 'SessionCreatedResponse'),
    ('POST', 'sessions/revoke'): _Route(
        _post_session_revoke, 'admin_sessions', 'sessions.revoke',
        'portal_session_revoke', 'SessionRevokeResponse'),
    ('POST', 'sessions/revoke-all'): _Route(
        _post_session_revoke_all, 'admin_sessions', 'sessions.revoke-all',
        'portal_session_revoke_all', 'SessionRevokeResponse', True),
    # Host power — MeshCentral/RustDesk parity. Step-up gated: a guest
    # or a stolen session must never be able to halt the host; WoL is
    # included (a spoofed packet can only wake, but the endpoint still
    # gets the same treatment because it emits a broadcast).
    ('POST', 'power'): _Route(
        _post_power, 'admin:*', 'power', 'power_action',
        'PowerActionResponse', True),
    ('POST', 'power/wol'): _Route(
        _post_power_wol, 'admin:*', 'power', 'power_wol',
        'WolResponse'),
    # Desktop capture — MeshCentral "Take screenshot"/recording parity.
    # The RFB capture client opens its own shared session against the
    # loopback VNC server; recordings are forensic material, so delete
    # is step-up bound.
    ('GET', 'desktop/screenshot'): _Route(
        _get_screenshot, 'admin:*', 'power', 'desktop_screenshot',
        'BinaryResponse'),
    ('GET', 'recordings'): _Route(
        _get_recordings, 'admin:*', 'default', None,
        'RecordingListResponse'),
    ('POST', 'recordings'): _Route(
        _post_recordings, 'admin:*', 'power', 'recording_start',
        'RecordingStartResponse'),
    ('GET', 'recordings/{id}'): _Route(
        _get_recording, 'admin:*', 'default', 'recording_download',
        'BinaryResponse'),
    ('POST', 'recordings/{id}/stop'): _Route(
        _post_recording_stop, 'admin:*', 'power', 'recording_stop',
        'RecordingStopResponse'),
    ('DELETE', 'recordings/{id}'): _Route(
        _delete_recording, 'admin:*', 'power', 'recording_delete',
        'RecordingDeleteResponse', True),
    ('POST', 'logout'): _Route(
        _post_logout, 'operator', 'default', 'portal_logout',
        'LogoutResponse'),
    ('POST', 'step-up'): _Route(
        _post_step_up, 'operator', 'stepup', 'step_up_granted',
        'StepUpResponse'),
    # Operator management — {username} is a path parameter resolved
    # by _dispatch into handler._api_params.
    ('GET', 'operators/{username}'): _Route(
        _get_operator_detail, 'admin_users', 'default', None,
        'OperatorResponse'),
    ('GET', 'operators/{username}/passkeys'): _Route(
        _get_operator_passkeys, 'operator', 'default', None,
        'PasskeyPageResponse'),
    ('POST', 'operators/{username}/passkeys/register/begin'): _Route(
        _post_passkey_register_begin, 'operator', 'passkeys.register',
        'passkey_register_begin', 'PasskeyOptionsResponse', True),
    ('POST', 'operators/{username}/passkeys/register/complete'): _Route(
        _post_passkey_register_complete, 'operator',
        'passkeys.register', 'passkey_registered',
        'PasskeyRegisteredResponse', True),
    ('PATCH', 'operators/{username}/passkeys/{credential_ref}'): _Route(
        _patch_passkey, 'operator', 'passkeys.manage',
        'passkey_renamed', 'PasskeyRenamedResponse'),
    ('DELETE', 'operators/{username}/passkeys/{credential_ref}'): _Route(
        _delete_passkey, 'operator', 'passkeys.manage',
        'passkey_revoked', 'DeleteResponse', True),
    ('POST', 'operators'): _Route(
        _post_operator_create, 'admin_users', 'operators.create',
        'operator_created', 'OperatorResponse', True),
    ('PATCH', 'operators/{username}'): _Route(
        _patch_operator, 'admin_users', 'operators.update',
        'operator_updated', 'OperatorResponse'),
    ('DELETE', 'operators/{username}'): _Route(
        _delete_operator, 'admin_users', 'operators.delete',
        'operator_deleted', 'DeleteResponse', True),
    ('POST', 'operators/{username}/sessions/revoke-all'): _Route(
        _post_operator_revoke_sessions, 'admin_users',
        'operators.sessions_revoke', 'operator_sessions_revoked',
        'SessionRevokeResponse', True),
    # Destructive-op ledger + operator restore (tombstone recovery).
    ('GET', 'jobs'): _Route(
        _get_jobs, 'admin_audit', 'default', None,
        'JobPageResponse'),
    ('GET', 'jobs/{jid}'): _Route(
        _get_job_detail, 'admin_audit', 'default', None,
        'JobDetailResponse'),
    ('GET', 'operators/deleted'): _Route(
        _get_operators_deleted, 'admin_users', 'default', None,
        'DeletedOperatorsResponse'),
    ('POST', 'operators/{username}/restore'): _Route(
        _post_operator_restore, 'admin_users', 'operators.create',
        'operator_restored', 'OperatorResponse', True),
    # OS-level runtime accounts surfaced to the admin SPA.
    ('GET', 'system-users'): _Route(
        _get_system_users, 'admin_users', 'default', None,
        'SystemUserPageResponse'),
    ('POST', 'system-users'): _Route(
        _post_system_user_create, 'admin_users', 'system_users.manage',
        'user_create', 'SystemUserCreatedResponse', True),
    ('DELETE', 'system-users/{username}'): _Route(
        _delete_system_user, 'admin_users', 'system_users.manage',
        'user_delete', 'DeleteResponse', True),
    # --- Operations parity with the CLI ----------------------------------
    # Version/status.
    ('GET', 'version'): _Route(
        _get_version, 'session', 'default', None, 'VersionResponse'),
    ('GET', 'lifecycle'): _Route(
        _get_lifecycle, 'operator', 'default', None,
        'LifecycleStatusResponse'),
    ('POST', 'lifecycle'): _Route(
        _post_lifecycle, 'admin:*', 'lifecycle', 'lifecycle_action',
        'LifecycleActionResponse', True),
    # Backups — create/verify/restore over ``core.backup``; names are
    # resolved server-side (basename allowlist) so the wire value never
    # reaches the filesystem.
    ('POST', 'backups'): _Route(
        _post_backup_create, 'admin:*', 'backups.write',
        'backup_create', 'BackupCreatedResponse', True),
    ('POST', 'backups/verify'): _Route(
        _post_backup_verify, 'admin:*', 'default',
        'backup_verify', 'BackupVerifyResponse'),
    ('POST', 'backups/restore'): _Route(
        _post_backup_restore, 'admin:*', 'backups.write',
        'backup_restore', 'BackupRestoreResponse', True),
    # Secrets — status/redact are admin reads; rotations are step-up.
    ('GET', 'secrets'): _Route(
        _get_secrets, 'admin:*', 'default', None, 'SecretsResponse'),
    ('GET', 'secrets/{name}'): _Route(
        _get_secret_redact, 'admin:*', 'default', None,
        'SecretRedactResponse'),
    ('POST', 'secrets/{name}/rotate'): _Route(
        _post_secret_rotate, 'admin:*', 'secrets.rotate',
        'secret_rotate', 'SecretRotateResponse', True),
    ('POST', 'secrets/rotate-signing'): _Route(
        _post_secrets_rotate_signing, 'admin:*', 'secrets.rotate',
        'signing_key_rotate', 'SigningRotateResponse', True),
    ('POST', 'secrets/check'): _Route(
        _post_secrets_check, 'admin:*', 'default',
        'secrets_check', 'SecretsCheckResponse'),
    ('POST', 'secrets/recovery-codes'): _Route(
        _post_recovery_codes, 'admin:*', 'secrets.rotate',
        'recovery_codes_generate', 'RecoveryCodesResponse', True),
    # Config inspector — explain/validate/diff are reads; migrate
    # mutates .env so it gets step-up.
    ('GET', 'config/effective'): _Route(
        _get_config_effective, 'admin_config', 'default', None,
        'ConfigPageResponse'),
    ('GET', 'config/explain/{name}'): _Route(
        _get_config_explain, 'admin_config', 'default', None,
        'ConfigExplainResponse'),
    ('GET', 'config/validate'): _Route(
        _get_config_validate, 'admin_config', 'default', None,
        'ConfigValidateResponse'),
    ('GET', 'config/diff'): _Route(
        _get_config_diff, 'admin_config', 'default', None,
        'ConfigDiffResponse'),
    ('POST', 'config/migrate'): _Route(
        _post_config_migrate, 'admin_config', 'config.write',
        'config_migrate', 'ConfigMigrateResponse', True),
    # Self-upgrade — long-running pip work under a job-ledger entry.
    ('GET', 'upgrade'): _Route(
        _get_upgrade, 'operator', 'default', None, 'UpgradeResponse'),
    ('POST', 'upgrade'): _Route(
        _post_upgrade, 'admin:*', 'upgrade', 'upgrade_run',
        'UpgradeRunResponse', True),
    ('POST', 'upgrade/rollback'): _Route(
        _post_upgrade_rollback, 'admin:*', 'upgrade',
        'upgrade_rollback', 'UpgradeRollbackResponse', True),
}

# Operator capabilities the registry may reference — anything else is
# a configuration bug a contract test catches.
_KNOWN_PERMS = {
    'operator', 'admin_sessions', 'admin_audit', 'admin_config',
    'admin_users',
    # Unauthenticated surface — login ceremonies only.
    'public',
    # Any authenticated portal identity — operator or share session.
    'session',
    # System-wide gate — only the umbrella holder may touch it.
    'admin:*',
}


_TEMPLATE_ROUTES = None


def _template_routes():
    """Compile ``{name}`` path templates in _ROUTES to regexes once.

    Segments like ``operators/{username}`` match a single non-empty
    path segment; captured params are stashed on
    ``handler._api_params`` for the handler.
    """
    global _TEMPLATE_ROUTES
    if _TEMPLATE_ROUTES is None:
        import re
        compiled = []
        for (method, rel), spec in _ROUTES.items():
            if '{' not in rel:
                continue
            pattern = '/'.join(
                f'(?P<{seg[1:-1]}>[^/]+)'
                if seg.startswith('{') and seg.endswith('}')
                else re.escape(seg)
                for seg in rel.split('/'))
            compiled.append((method, re.compile(f'^{pattern}$'), spec))
        _TEMPLATE_ROUTES = compiled
    return _TEMPLATE_ROUTES


def is_public_route(method: str, path: str) -> bool:
    """True when ``method path`` resolves to a ``perm='public'``
    route — the caller (landing) must let these past the portal
    auth gate, since login ceremonies predate any session."""
    rel = path[len(_API_PREFIX):] if path.startswith(_API_PREFIX) \
        else path
    spec, _ = _match_route(method, rel)
    return spec is not None and spec.perm == 'public'


def _match_route(method: str, rel: str):
    """Resolve ``(method, path)`` to ``(spec, params)`` — literal
    routes first, then compiled ``{param}`` templates."""
    spec = _ROUTES.get((method, rel))
    if spec is not None:
        return spec, {}
    for rmethod, regex, rspec in _template_routes():
        if rmethod == method:
            m = regex.match(rel)
            if m:
                return rspec, m.groupdict()
    return None, {}


def _deny_step_up(handler, operator: dict, method: str,
                  rel: str) -> None:
    """403 + machine-readable code — the SPA opens the step-up
    dialog instead of treating it as a permission failure."""
    from vnc_remote_secure.security.audit import audit_event
    audit_event(
        'step_up_required',
        user=operator.get('username', '?'),
        detail=f'{method} {rel}')
    handler.send_json_error(
        'Step-up authentication required', 403, code='STEP_UP_REQUIRED')


def _dispatch(handler, method: str, path: str, query: dict) -> bool:
    """Central dispatch: rate limit -> auth/capability -> handler.

    Returns True when the route was handled (response written), False
    when ``path`` matches no route.
    """
    rel = path[len(_API_PREFIX):]
    spec, params = _match_route(method, rel)
    if spec is None:
        return False
    if not _rate_limit(handler, spec.scope):
        return True
    if spec.perm == 'public':
        # Unauthenticated surface (login ceremonies): no operator
        # gate — handlers run _public_gate for Origin/Sec-Fetch
        # checks; CSRF is meaningless before a session exists.
        handler._api_params = params
        spec.fn(handler, query)
        return True
    if spec.perm == 'session':
        # Any authenticated portal identity — an activated share-link
        # cookie or an operator session. GETs already ran
        # _portal_identity in do_GET; the explicit re-check keeps
        # direct dispatch paths (mutations, tests) from trusting the
        # caller to have run it.
        if handler._valid_ephemeral_cookie():
            handler._api_ephemeral = True
            handler._api_operator = None
        else:
            operator = (handler._operator_gate(None)
                        if method != 'GET'
                        else _operator(handler, None))
            if operator is None:
                return True
            handler._api_ephemeral = False
            handler._api_operator = operator
        handler._api_params = params
        spec.fn(handler, query)
        return True
    if method != 'GET':
        # _operator_gate runs operator auth + Origin + Sec-Fetch-Site
        # + the nonce-bound CSRF check + the capability check.
        perm = None if spec.perm == 'operator' else spec.perm
        operator = handler._operator_gate(perm)
        if operator is None:
            return True
        handler._api_operator = operator
        # Destructive/mass operations require a recent
        # authentication, not just a valid session (POST step-up
        # grants 5 min).
        from vnc_remote_secure.security.step_up_auth import needs_step_up
        if spec.step_up and needs_step_up(
                operator.get('username', '')):
            _deny_step_up(handler, operator, method, rel)
            return True
    elif spec.perm is not None:
        cap = None if spec.perm == 'operator' else spec.perm
        operator = _operator(handler, cap)
        if operator is None:
            return True
        handler._api_operator = operator
    handler._api_params = params
    spec.fn(handler, query)
    return True


def handle_get(handler, path: str, query: dict) -> bool:
    """Dispatch a GET under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'GET', path, query)


def handle_post(handler, path: str) -> bool:
    """Dispatch a POST under /api/v1/. Returns True when handled."""
    return _dispatch(handler, 'POST', path, {})
