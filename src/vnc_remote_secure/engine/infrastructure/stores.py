"""Infrastructure adapters — the ONLY place engine code may touch
``security/*``.

Application use cases depend on these narrow accessors; when the
persistence layer moves (SQLite store, secret backend, remote audit
sink) only this module changes. Each function is intentionally thin —
a delegation, not a re-implementation.
"""
from __future__ import annotations


def env(name: str, default: str = '') -> str:
    """Configuration read — env access stays in the infrastructure
    layer so use cases never touch ``os.environ`` directly."""
    import os
    return os.environ.get(name, default)


# --- Ephemeral share-link sessions -----------------------------------


def session_store():
    """The process/shared session store (create/get/revoke/list)."""
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store
    return get_session_store()


def revoke_ephemeral_token(token_id: str) -> bool:
    from vnc_remote_secure.security.ephemeral_sessions import revoke_session
    return revoke_session(token_id)


def session_refresh(store) -> None:
    """Re-read persisted sessions when the backend supports it —
    tests and future adapters may not need the hook."""
    fn = getattr(store, '_load_if_changed', None)
    if callable(fn):
        fn()


def session_roles() -> dict:
    """Role → default permission set for share links."""
    from vnc_remote_secure.security.ephemeral_sessions import ROLES
    return ROLES


def expand_session_permissions(perms: set) -> set:
    """Expand umbrella permissions (e.g. admin:* covers all)."""
    from vnc_remote_secure.security.ephemeral_sessions import expand_permissions
    return expand_permissions(perms)


# --- Operator accounts ------------------------------------------------


def operator_load_store() -> dict:
    from vnc_remote_secure.security.operator_users import load_store
    return load_store()


def operator_add(username: str, password: str, role: str) -> None:
    from vnc_remote_secure.security.operator_users import add_user
    return add_user(username, password, role)


def operator_set_disabled(username: str, disabled: bool) -> bool:
    from vnc_remote_secure.security.operator_users import set_disabled
    return set_disabled(username, disabled)


def operator_remove(username: str) -> bool:
    from vnc_remote_secure.security.operator_users import remove_user
    return remove_user(username)


def operator_roles() -> dict:
    from vnc_remote_secure.security.operator_users import ROLE_PERMISSIONS
    return ROLE_PERMISSIONS


def operator_set_password(username: str, password: str) -> bool:
    from vnc_remote_secure.security.operator_users import set_password
    return set_password(username, password)


def operator_set_role(username: str, role: str) -> bool:
    from vnc_remote_secure.security.operator_users import set_role
    return set_role(username, role)


def operator_permissions(username: str) -> set:
    from vnc_remote_secure.security.operator_users import get_permissions
    return get_permissions(username)


# --- Revocation (shared state) ----------------------------------------


def shared_backend():
    from vnc_remote_secure.security.shared_state import get_backend
    return get_backend()


# --- Maintenance -------------------------------------------------------


def maintenance_active() -> bool:
    from vnc_remote_secure.security.maintenance import maintenance_active
    return maintenance_active()


def maintenance_info() -> dict | None:
    from vnc_remote_secure.security.maintenance import maintenance_info
    return maintenance_info()


def maintenance_set(active: bool, by: str, reason: str = '',
                    drain_at: float | None = None) -> None:
    from vnc_remote_secure.security.maintenance import set_maintenance
    return set_maintenance(active, by=by, reason=reason,
                           drain_at=drain_at)


def maintenance_drain() -> int:
    from vnc_remote_secure.security.maintenance import drain_sessions
    return drain_sessions()


# --- Audit -------------------------------------------------------------


def audit(event: str, user: str, detail: str = '',
          result: str = '') -> None:
    from vnc_remote_secure.security.audit import audit_event
    kw = {'detail': detail}
    if result:
        kw['result'] = result
    audit_event(event, user=user, **kw)


# --- Step-up -----------------------------------------------------------


def step_up_error(username: str, action: str) -> str | None:
    from vnc_remote_secure.security.step_up_auth import require_step_up
    return require_step_up(username, action)


# --- WebAuthn credentials ----------------------------------------------


def credential_list(username: str) -> list:
    from vnc_remote_secure.security.webauthn import list_credentials
    return list_credentials(username)


def credential_delete(credential_id: str, username: str) -> bool:
    from vnc_remote_secure.security.webauthn import delete_credential
    return delete_credential(credential_id, username)


def credential_rename(credential_id: str, name: str) -> bool:
    from vnc_remote_secure.security.webauthn import rename_credential
    return rename_credential(credential_id, name)


def webauthn_gate_error() -> str | None:
    from vnc_remote_secure.security.webauthn import rp_config_error, webauthn_available
    if not webauthn_available():
        return 'WebAuthn is not enabled'
    return rp_config_error()


def webauthn_begin(username: str, rp_id: str, rp_name: str) -> dict:
    from vnc_remote_secure.security.webauthn import begin_registration
    return begin_registration(username, username, rp_id, rp_name)


def webauthn_complete(username: str, credential: dict, rp_id: str,
                      origin: str, name: str) -> tuple[bool, str]:
    from vnc_remote_secure.security.webauthn import complete_registration
    return complete_registration(username, credential, rp_id, origin,
                                 name=name)


# --- MFA policy ----------------------------------------------------------


def mfa_required() -> bool:
    from vnc_remote_secure.security.mfa import mfa_required_for_login
    return mfa_required_for_login()


def mfa_available() -> bool:
    from vnc_remote_secure.security.mfa import is_mfa_enabled
    return is_mfa_enabled()


# --- System (OS) users -------------------------------------------------
# The platform adapter owns the OS calls; the engine only sees narrow
# primitives. Validation lives in core.validation — a domain concern.

def system_users_list() -> list:
    """Non-reserved OS users: {username, uid|None, home|None}.

    Linux reads pwd (UID >= 100, non-reserved); Windows delegates to
    the adapter's list_users()."""
    import platform as _platform

    from vnc_remote_secure.core.constants import (
        RESERVED_USERNAMES,
        WINDOWS_BUILTIN_USERNAMES,
    )
    users = []
    if _platform.system() == 'Windows':
        try:
            from vnc_remote_secure.platform.windows.permissions import list_users
            for u in list_users():
                name = u.get('username', '')
                if (name and name not in RESERVED_USERNAMES
                        and name not in WINDOWS_BUILTIN_USERNAMES):
                    users.append({
                        'username': name,
                        'uid': u.get('uid'),
                        'home': u.get('home'),
                    })
        except Exception:  # noqa: BLE001 - listing is best-effort
            pass
        return users
    try:
        import pwd
        for u in pwd.getpwall():
            if u.pw_uid >= 100 and u.pw_name not in RESERVED_USERNAMES:
                users.append({
                    'username': u.pw_name,
                    'uid': u.pw_uid,
                    'home': u.pw_dir,
                })
    except (ImportError, AttributeError):
        pass
    return users


def system_user_create(username: str, password: str) -> None:
    """Create the OS account and set its password via the adapter."""
    import platform as _platform

    from vnc_remote_secure.platform.base import get_adapter
    if not get_adapter().create_runtime_user(username):
        raise RuntimeError('user creation failed')
    if _platform.system() == 'Windows':
        from vnc_remote_secure.platform.windows.permissions import set_user_password
    else:
        from vnc_remote_secure.platform.linux.permissions import set_user_password
    set_user_password(username, password)


def system_user_delete(username: str) -> bool:
    from vnc_remote_secure.platform.base import get_adapter
    return bool(get_adapter().remove_runtime_user(username))


def system_usernames_reserved() -> set:
    from vnc_remote_secure.core.constants import (
        RESERVED_USERNAMES,
        WINDOWS_BUILTIN_USERNAMES,
    )
    return RESERVED_USERNAMES | WINDOWS_BUILTIN_USERNAMES


def system_current_user() -> str:
    import getpass
    return getpass.getuser()


# --- Read-model backing -------------------------------------------------
# Pure reads the admin views consume — the application layer shapes
# them; transport stays out of the store details.

def audit_read(limit: int, event: str | None = None,
               before_seq: int | None = None,
               user: str | None = None,
               result: str | None = None) -> list:
    from vnc_remote_secure.security.audit import get_audit_entries
    return get_audit_entries(
        limit=limit, event=event, before_seq=before_seq,
        user=user, result=result)


def audit_verify_chain() -> tuple[bool, str]:
    from vnc_remote_secure.security.audit import verify_chain
    return verify_chain()


def config_effective() -> list:
    """Redacted effective-config entries (ConfigEntry dicts)."""
    from vnc_remote_secure.core.config_inspector import compute_effective_config
    return compute_effective_config()


def backups_paths() -> list:
    """Backup file paths (stat'ing is left to the transport)."""
    from vnc_remote_secure.core.backup import list_backups
    return list(list_backups())


def posture_report() -> dict:
    from vnc_remote_secure.security.posture import calculate_posture
    return calculate_posture()


def doctor_report() -> dict:
    from vnc_remote_secure.core.doctor import run_doctor
    return run_doctor(as_json=True)


def health_report() -> dict:
    from vnc_remote_secure.monitoring.health import get_all_health
    return get_all_health()


# --- Job tracking + operator tombstones ---------------------------------

def job_start(kind: str, actor: str, target: str = '',
              detail: str = '') -> str:
    from vnc_remote_secure.security.jobs import job_start
    return job_start(kind, actor, target, detail)


def job_finish(jid: str, detail: str = '') -> None:
    from vnc_remote_secure.security.jobs import job_finish
    job_finish(jid, detail)


def job_fail(jid: str, error: str) -> None:
    from vnc_remote_secure.security.jobs import job_fail
    job_fail(jid, error)


def jobs_list(limit: int = 100) -> list:
    from vnc_remote_secure.security.jobs import list_jobs
    return list_jobs(limit)


def tombstone_save(username: str, record: dict) -> None:
    from vnc_remote_secure.security.jobs import tombstone_save
    tombstone_save(username, record)


def tombstone_get(username: str) -> dict | None:
    from vnc_remote_secure.security.jobs import tombstone_get
    return tombstone_get(username)


def tombstone_remove(username: str) -> None:
    from vnc_remote_secure.security.jobs import tombstone_remove
    tombstone_remove(username)


def tombstones() -> list:
    from vnc_remote_secure.security.jobs import tombstones
    return tombstones()


# --- Portal read-model inputs ----------------------------------------


def portal_config() -> dict:
    """The runtime config (lazy, honours .env reload)."""
    from vnc_remote_secure.core.portal import portal_config as _pc
    return _pc()


def service_list(protocol: str, external_base: str | None = None) -> list:
    """Service cards for the portal page (name/url/port/running)."""
    from vnc_remote_secure.core.portal import build_service_list
    return build_service_list(protocol, external_base)


def lan_ips() -> list:
    from vnc_remote_secure.core.portal import get_lan_ips
    return get_lan_ips()


def system_metrics() -> dict:
    from vnc_remote_secure.core.portal import get_system_metrics
    return get_system_metrics()


def port_listening(port: int, host: str = '127.0.0.1') -> bool:
    from vnc_remote_secure.core.portal import check_port
    return check_port(port, host)


def is_windows() -> bool:
    from vnc_remote_secure.platform.detection import is_windows as _iw
    return _iw()


def vnc_effective_port() -> int:
    """The RFB port actually bound — TigerVNC derives 5900+display on
    Linux regardless of an explicit VNC_PORT."""
    from vnc_remote_secure.core.portal import vnc_effective_port as _vp
    return _vp()


def tls_available(cfg: dict) -> bool:
    """True when the configured cert/key yield a usable TLS context."""
    from vnc_remote_secure.core.portal import tls_available as _ta
    return _ta(cfg)


def session_preview(signed: str) -> dict | None:
    """Non-consuming grant summary for a share-link token."""
    from vnc_remote_secure.security.ephemeral_sessions import preview_session
    return preview_session(signed)


def activate_share_session(signed: str, client_ip: str | None = None):
    """Consume a share-link token; returns the internal session token."""
    from vnc_remote_secure.security.ephemeral_sessions import activate_ephemeral_session
    return activate_ephemeral_session(signed, client_ip=client_ip)


def audio_capture_active() -> bool:
    """True while the audio service is capturing the mic — reads the
    shared-state flag directly (the engine must not import services/*;
    services/audio refreshes 'audio_indicator:capture' with a 120 s
    TTL while ffmpeg runs)."""
    try:
        return bool(shared_backend().get('audio_indicator', 'capture'))
    except Exception:  # noqa: BLE001 - flag is best-effort
        return False


def gamepad_stopped() -> bool:
    """Shared kill-switch flag read by the gamepad service per message."""
    try:
        return bool(shared_backend().get('gamepad', 'stopped'))
    except Exception:  # noqa: BLE001 - flag is best-effort
        return False


def gamepad_set_stopped(stop: bool) -> None:
    """Set/clear the shared kill-switch flag (1y ttl while stopped)."""
    if stop:
        shared_backend().set_ttl('gamepad', 'stopped', '1', 86400 * 365)
    else:
        shared_backend().delete('gamepad', 'stopped')
