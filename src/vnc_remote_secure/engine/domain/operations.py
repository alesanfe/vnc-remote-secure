"""Canonical operation catalog — the single declaration of every
manageable action the product exposes.

The rule: CLI and UI offer equivalent capability because both invoke
the same use case — not because they re-implement it. This catalog is
what makes that rule *checkable*:

* every `supports_api` operation MUST have a ``_ROUTES`` entry whose
  ``perm``/``step_up``/``audit`` fields match the spec here;
* every `supports_cli` operation MUST have a ``vnc-remote`` command;
* every ``risk in (high, critical)`` operation MUST declare
  ``confirmation_type != 'none'`` and a bound step-up policy;
* every ``execution_mode in (job, deferred)`` operation MUST emit a
  job-ledger record.

Transports (``services/api_v1.py``, ``cli/commands/*``) and the React
wizards consult this metadata — they never hardcode their own policy.

Only ``engine/domain``-level data lives here; no imports outside
stdlib so the catalog is importable from every layer.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationSpec:
    """Declared behavior of one manageable operation.

    Fields
    ------
    operation_id
        Stable machine name (``backup.restore``) — the audit detail,
        step-up grant binding and job ``kind`` key off it.
    title
        Short operator-facing label.
    risk
        ``low`` | ``moderate`` | ``high`` | ``critical``.
    required_capability
        Operator capability gate ('' = any authenticated identity,
        'operator' = operator account, 'admin_*'/'admin:*').
    authentication_policy
        ``''`` session only | ``stepup`` recent-auth window |
        ``stepup-bound`` single-use grant tied to
        operation(+resource)+session.
    supports_cli / supports_api / supports_ui
        Transports allowed to expose the operation. ``False`` means
        "by design", not "missing".
    execution_mode
        ``sync`` — result in the response | ``job`` — queued on the
        persistent job ledger, claimed by an executor |
        ``deferred`` — detached child process (lifecycle actions
        that kill the portal serving the request).
    confirmation_type
        ``none`` | ``simple`` | ``typed`` — what the UI must collect
        before submitting (CLI uses ``--yes``/interactive prompts).
    job_type
        Job-ledger kind; '' = no job record.
    audit_event
        Audit event name the use case emits on completion.
    reversible
        ``yes`` | ``partially`` | ``no``.
    cli_command
        The canonical ``vnc-remote`` invocation (informational +
        parity-matrix generation).
    api_route
        ``METHOD /api/v1/<path>`` when ``supports_api``.
    """

    operation_id: str
    title: str
    risk: str
    required_capability: str
    authentication_policy: str = ''
    supports_cli: bool = True
    supports_api: bool = True
    supports_ui: bool = True
    execution_mode: str = 'sync'
    confirmation_type: str = 'none'
    job_type: str = ''
    audit_event: str = ''
    reversible: str = 'no'
    cli_command: str = ''
    api_route: str = ''


def _op(operation_id, title, risk, capability, **kw) -> OperationSpec:
    return OperationSpec(operation_id=operation_id, title=title,
                         risk=risk, required_capability=capability, **kw)


# The registry — order matches the CLI command tree.
OPERATIONS: dict[str, OperationSpec] = {
    o.operation_id: o for o in [
        # --- Version / status ------------------------------------------
        _op('system.version', 'Ver versión', 'low', 'session',
            execution_mode='sync', cli_command='version',
            api_route='GET /version', reversible='yes'),
        _op('system.status', 'Estado de servicios', 'low', 'operator',
            cli_command='status', api_route='GET /lifecycle',
            reversible='yes'),
        _op('system.doctor', 'Diagnóstico', 'low', 'operator',
            cli_command='doctor', api_route='GET /doctor',
            reversible='yes'),

        # --- Lifecycle ---------------------------------------------------
        _op('lifecycle.action', 'Arrancar/parar/reiniciar servicios',
            'critical', 'admin:*',
            authentication_policy='stepup-bound',
            execution_mode='deferred', confirmation_type='typed',
            job_type='lifecycle', audit_event='lifecycle_action',
            cli_command='start|stop|restart',
            api_route='POST /lifecycle', reversible='partially'),

        # --- Backups ------------------------------------------------------
        _op('backup.list', 'Listar backups', 'low', 'operator',
            cli_command='backup --list', api_route='GET /backups',
            reversible='yes'),
        _op('backup.create', 'Crear backup', 'moderate', 'admin:*',
            authentication_policy='stepup-bound',
            job_type='backup', audit_event='backup_create',
            confirmation_type='simple',
            cli_command='backup', api_route='POST /backups',
            reversible='yes'),
        _op('backup.verify', 'Verificar backup', 'low', 'admin:*',
            audit_event='backup_verify',
            cli_command='verify backup', api_route='POST /backups/verify',
            reversible='yes'),
        _op('backup.restore', 'Restaurar backup', 'critical', 'admin:*',
            authentication_policy='stepup-bound',
            execution_mode='job', confirmation_type='typed',
            job_type='restore', audit_event='backup_restore',
            cli_command='restore', api_route='POST /backups/restore',
            reversible='partially'),

        # --- Secrets ------------------------------------------------------
        _op('secrets.status', 'Estado de secretos', 'low', 'admin:*',
            cli_command='secrets status', api_route='GET /secrets',
            reversible='yes'),
        _op('secrets.redact', 'Ver secreto redactado', 'low', 'admin:*',
            cli_command='secrets redact',
            api_route='GET /secrets/{name}', reversible='yes'),
        _op('secrets.rotate', 'Rotar credencial', 'critical', 'admin:*',
            authentication_policy='stepup-bound',
            confirmation_type='typed', job_type='secret_rotate',
            audit_event='secret_rotate',
            cli_command='secrets rotate',
            api_route='POST /secrets/{name}/rotate',
            reversible='no'),
        _op('secrets.rotate_signing', 'Rotar clave de firma',
            'critical', 'admin:*', authentication_policy='stepup-bound',
            confirmation_type='simple', audit_event='signing_key_rotate',
            cli_command='secrets rotate-signing',
            api_route='POST /secrets/rotate-signing',
            reversible='yes'),
        _op('secrets.check', 'Comprobar TLS/permisos', 'low', 'admin:*',
            audit_event='secrets_check',
            cli_command='secrets check', api_route='POST /secrets/check',
            reversible='yes'),
        _op('secrets.recovery_codes', 'Códigos de recuperación MFA',
            'critical', 'admin:*', authentication_policy='stepup-bound',
            confirmation_type='simple', audit_event='recovery_codes_generate',
            cli_command='secrets recovery-codes',
            api_route='POST /secrets/recovery-codes', reversible='yes'),

        # --- Config --------------------------------------------------------
        _op('config.effective', 'Config efectiva', 'low', 'admin_config',
            cli_command='config show-effective',
            api_route='GET /config', reversible='yes'),
        _op('config.explain', 'Explicar variable', 'low', 'admin_config',
            cli_command='config explain',
            api_route='GET /config/explain/{name}', reversible='yes'),
        _op('config.validate', 'Validar configuración', 'low',
            'admin_config', cli_command='config validate',
            api_route='GET /config/validate', reversible='yes'),
        _op('config.diff', 'Diff de perfiles', 'low', 'admin_config',
            cli_command='config diff', api_route='GET /config/diff',
            reversible='yes'),
        _op('config.migrate', 'Migrar .env', 'high', 'admin_config',
            authentication_policy='stepup-bound',
            confirmation_type='simple', audit_event='config_migrate',
            cli_command='config migrate',
            api_route='POST /config/migrate', reversible='yes'),

        # --- Sessions / share links ---------------------------------------
        _op('session.create', 'Crear acceso temporal', 'high',
            'admin_sessions',
            confirmation_type='simple', audit_event='ephemeral_session_create',
            cli_command='session create', api_route='POST /sessions'),
        _op('session.revoke', 'Revocar sesión', 'moderate',
            'admin_sessions', confirmation_type='simple',
            audit_event='portal_session_revoke',
            cli_command='session revoke', api_route='POST /sessions/revoke'),
        _op('session.revoke_all', 'Revocar todas', 'high',
            'admin_sessions', authentication_policy='stepup',
            confirmation_type='typed',
            audit_event='portal_session_revoke_all',
            cli_command='session revoke --all',
            api_route='POST /sessions/revoke-all'),

        # --- Operators ------------------------------------------------------
        _op('operator.create', 'Crear operador', 'high', 'admin_users',
            authentication_policy='stepup', confirmation_type='simple',
            audit_event='operator_created',
            cli_command='operator add', api_route='POST /operators'),
        _op('operator.update', 'Editar operador', 'moderate', 'admin_users',
            confirmation_type='simple', audit_event='operator_updated',
            cli_command='operator passwd|role|disable|enable',
            api_route='PATCH /operators/{username}'),
        _op('operator.delete', 'Eliminar operador', 'high', 'admin_users',
            authentication_policy='stepup', confirmation_type='typed',
            audit_event='operator_deleted', reversible='partially',
            cli_command='operator remove',
            api_route='DELETE /operators/{username}'),
        _op('operator.restore', 'Restaurar operador', 'high', 'admin_users',
            authentication_policy='stepup', confirmation_type='simple',
            audit_event='operator_restored', reversible='yes',
            supports_cli=False,
            api_route='POST /operators/{username}/restore'),

        _op('operator.sessions_revoke_all', 'Revocar sesiones de operador',
            'moderate', 'admin_users', authentication_policy='stepup',
            confirmation_type='simple',
            audit_event='operator_sessions_revoked',
            supports_cli=False,
            api_route='POST /operators/{username}/sessions/revoke-all'),

        # --- System users (OS-level, step-up gated) -------------------------
        _op('system_user.create', 'Crear usuario de sistema', 'high',
            'admin_users', authentication_policy='stepup',
            confirmation_type='simple', audit_event='user_create',
            supports_cli=False,
            api_route='POST /system-users'),
        _op('system_user.delete', 'Eliminar usuario de sistema', 'high',
            'admin_users', authentication_policy='stepup',
            confirmation_type='typed', audit_event='user_delete',
            supports_cli=False,
            api_route='DELETE /system-users/{username}'),

        # --- Passkeys -------------------------------------------------------
        _op('passkey.register_begin', 'Iniciar registro passkey', 'high',
            'operator', authentication_policy='stepup',
            confirmation_type='simple', supports_cli=False,
            audit_event='passkey_register_begin',
            api_route='POST /operators/{username}/passkeys/register/begin',
            reversible='yes'),
        _op('passkey.register_complete', 'Completar registro passkey', 'high',
            'operator', authentication_policy='stepup',
            confirmation_type='simple', supports_cli=False,
            audit_event='passkey_registered',
            api_route='POST /operators/{username}/passkeys/register/complete',
            reversible='yes'),
        _op('passkey.revoke', 'Revocar passkey', 'high', 'operator',
            authentication_policy='stepup', confirmation_type='simple',
            supports_cli=False, audit_event='passkey_revoked',
            api_route='DELETE /operators/{username}/passkeys/{credential_ref}',
            reversible='yes'),

        # --- Maintenance ----------------------------------------------------
        _op('maintenance.toggle', 'Modo mantenimiento', 'high', 'admin:*',
            authentication_policy='stepup', confirmation_type='simple',
            audit_event='maintenance_changed',
            cli_command='maintenance on|off|status',
            api_route='POST /maintenance', reversible='yes'),

        # --- Upgrade ----------------------------------------------------------
        _op('upgrade.check', 'Comprobar actualización', 'low', 'operator',
            cli_command='upgrade --check', api_route='GET /upgrade',
            reversible='yes'),
        _op('upgrade.run', 'Actualizar paquete', 'critical', 'admin:*',
            authentication_policy='stepup-bound',
            execution_mode='job', confirmation_type='typed',
            job_type='upgrade', audit_event='upgrade_run',
            cli_command='upgrade', api_route='POST /upgrade',
            reversible='partially'),
        _op('upgrade.rollback', 'Rollback de upgrade', 'critical', 'admin:*',
            authentication_policy='stepup-bound',
            execution_mode='job', confirmation_type='typed',
            job_type='upgrade_rollback', audit_event='upgrade_rollback',
            cli_command='upgrade --rollback',
            api_route='POST /upgrade/rollback', reversible='yes'),

        # --- Host bootstrap — CLI-only BY DESIGN ----------------------------
        _op('host.install', 'Instalar y configurar', 'critical', '',
            supports_api=False, supports_ui=False,
            cli_command='install',
            reversible='partially',
            confirmation_type='typed'),
        _op('host.uninstall', 'Desinstalar', 'critical', '',
            supports_api=False, supports_ui=False,
            cli_command='uninstall',
            reversible='partially',
            confirmation_type='typed'),
        _op('host.service', 'Modo servicio (systemd/SCM)', 'moderate', '',
            supports_api=False, supports_ui=False,
            cli_command='service --run', reversible='yes'),

        # --- UI-internal (no CLI counterpart — browser ceremonies) --------
        _op('ui.step_up', 'Step-up grant', 'low', 'operator',
            supports_cli=False, api_route='POST /step-up',
            reversible='yes'),
    ]
}


def get_operation(operation_id: str) -> OperationSpec | None:
    return OPERATIONS.get(operation_id)


def api_operations() -> dict[str, OperationSpec]:
    return {k: v for k, v in OPERATIONS.items() if v.supports_api}


def cli_operations() -> dict[str, OperationSpec]:
    return {k: v for k, v in OPERATIONS.items() if v.supports_cli}


def step_up_bound_operations() -> dict[str, OperationSpec]:
    return {k: v for k, v in OPERATIONS.items()
            if v.authentication_policy == 'stepup-bound'}


def parity_matrix() -> list[dict]:
    """Every operation × its declared transports — feeds the generated
    parity document and the contract test."""
    return [
        {
            'operation': o.operation_id,
            'title': o.title,
            'risk': o.risk,
            'cli': o.cli_command or '-',
            'api': o.api_route or '-',
            'ui': o.supports_ui,
            'perm': o.required_capability,
            'step_up': o.authentication_policy or 'session',
            'execution': o.execution_mode,
            'audit': o.audit_event or '-',
            'reversible': o.reversible,
        }
        for o in OPERATIONS.values()
    ]
