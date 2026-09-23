"""Configuration inspector with provenance tracking.

Shows the effective value of each configuration variable and where it
came from (env file, profile, platform default, security policy, etc.).

Layers (in priority order, first match wins):
1. Environment variable (os.environ) — highest priority
2. .env file (loaded by load_env_file)
3. Security profile (applied by apply_profile)
4. Platform defaults (Linux/Windows)
5. Hardcoded defaults (constants.py)
"""
import logging
import os

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
    TIGERVNC_BASE_PORT,
    WEAK_PASSWORDS,
)
from vnc_remote_secure.security.profiles import _PROFILE_ALIASES, PROFILES

logger = logging.getLogger(__name__)

# Variables that are credentials (redacted in output).
# Aliased from security.redaction.SECRET_VARS — the canonical list —
# so secret names are declared in exactly one place.
from vnc_remote_secure.security.redaction import SECRET_VARS

CREDENTIAL_VARS = SECRET_VARS

# Security-critical variables that cannot be overridden in hardened
# profiles — kept in sync with the runtime via
# ``security.profiles.locked_vars_for``.
LOCKED_VARS = {
    'BACKEND_BIND_HOST': '127.0.0.1',
}


def _resolve_profile_name(env_snapshot: dict[str, str]) -> str:
    """Resolve the effective profile from a snapshot of env vars.

    Mirrors ``security.profiles.resolve_profile()`` but against the
    provided snapshot: honours the ``VNC_REMOTE_PROFILE`` fallback and
    resolves legacy aliases (home-lan, private-vpn, ...) to canonical
    names so profile-scoped checks agree with apply_profile() at
    runtime.
    """
    name = (env_snapshot.get('SECURITY_PROFILE')
            or env_snapshot.get('VNC_REMOTE_PROFILE')
            or 'development')
    return _PROFILE_ALIASES.get(name, name)


def _locked_vars_for_profile(profile_name: str) -> dict[str, str]:
    """Return the runtime lock set for ``profile_name``.

    Delegates to ``security.profiles.locked_vars_for`` so the inspector
    reports exactly the overrides ``apply_profile`` enforces
    (BACKEND_BIND_HOST, TLS_ENABLED, DISABLE_SSL, NGINX_ENABLED and —
    for profiles mandating MFA — MFA_REQUIRED). Falls back to the
    minimal static set when the profiles module cannot be loaded.
    """
    try:
        from vnc_remote_secure.security.profiles import locked_vars_for
        return locked_vars_for(profile_name)
    except Exception:  # noqa: BLE001 - inspection must not hard-fail
        return LOCKED_VARS


def _get_platform_defaults() -> dict[str, str]:
    """Return the platform-aware default values.

    Reads ``config/defaults/common.env`` AND
    ``config/defaults/{linux,windows}.env`` — the same pair
    ``config._load_platform_defaults()`` loads at runtime (platform
    file overrides common). Reading only the platform file would
    misreport the provenance of every common default
    (``VNC_DISPLAY``, ``SHARED_STATE_BACKEND``, …) as unset.
    """
    from vnc_remote_secure.core.config import _parse_env_file

    platform_file = 'windows.env' if os.name == 'nt' else 'linux.env'
    candidates = []
    try:
        from importlib.resources import files
        candidates.append(
            str(files('vnc_remote_secure') / 'config' / 'defaults'))
    except Exception:  # noqa: BLE001 - package resources unavailable
        pass
    candidates.append(os.path.join(
        os.path.dirname(__file__), '..', 'config', 'defaults'))
    for defaults_dir in candidates:
        if defaults_dir and os.path.isdir(defaults_dir):
            merged: dict[str, str] = {}
            for name in ('common.env', platform_file):
                path = os.path.join(defaults_dir, name)
                if os.path.isfile(path):
                    merged.update(_parse_env_file(path))
            if merged:
                return merged
    return {}


def _get_hardcoded_defaults() -> dict[str, str]:
    """Return hardcoded default values from constants."""
    return {
        'BIND_HOST': DEFAULT_BIND_HOST,
        'NOVNC_PORT': str(DEFAULT_NOVNC_PORT),
        'TTYD_PORT': str(DEFAULT_TTYD_PORT),
        'LANDING_PORT': str(DEFAULT_LANDING_PORT),
        'HEALTH_WEB_PORT': str(DEFAULT_HEALTH_PORT),
        'VNC_PORT': str(DEFAULT_VNC_PORT),
    }


# Per-service bind hosts that fall back to BIND_HOST before the
# loopback constant — mirrors ``config._env_host`` so that
# ``show-effective`` reports the value the service actually binds
# (e.g. ``BIND_HOST=0.0.0.0`` propagates to these) instead of a
# misleading 'not-set'.
_SERVICE_HOST_VARS = {
    'AUDIO_STREAM_HOST', 'GAMEPAD_HOST', 'HEALTH_WEB_HOST',
    'LANDING_HOST', 'SERVE_NOVNC_HOST', 'TTYD_HOST', 'USER_UI_HOST',
}


def _get_profile_values(profile_name: str) -> dict[str, str]:
    """Return the values set by a security profile."""
    resolved = _PROFILE_ALIASES.get(profile_name, profile_name)
    profile = PROFILES.get(resolved, {})
    return {k: str(v) for k, v in profile.items() if k != 'description'}


def _redact_value(name: str, value: str) -> str:
    """Redact credential values."""
    if name in CREDENTIAL_VARS and value:
        return f'[REDACTED:{len(value)}chars]'
    return value


def _load_env_file_values() -> dict[str, str]:
    """Parse the project ``.env`` into a dict (no env mutation)."""
    env_file_values: dict[str, str] = {}
    from vnc_remote_secure.core.paths import find_project_root
    env_path = os.path.join(find_project_root(), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    key, _, val = line.partition('=')
                    key = key.strip()
                    val = val.strip()
                    if val and val[0] in '"\'' and val[-1] == val[0]:
                        val = val[1:-1]
                    if val.startswith('$('):
                        continue
                    env_file_values[key] = val
        except (OSError, ValueError):
            logger.debug("Failed to read .env file", exc_info=True)
    return env_file_values


def _schema_known_vars() -> set:
    """Return variable names declared in the JSON schema."""
    import json as _json
    candidates = []
    try:
        from importlib.resources import files
        candidates.append(str(
            files('vnc_remote_secure') / 'config' / 'schema'
            / 'config.schema.json'))
    except Exception:  # noqa: BLE001
        pass
    candidates.append(os.path.join(
        os.path.dirname(__file__), '..', 'config', 'schema',
        'config.schema.json'))
    for path in candidates:
        try:
            with open(path, encoding='utf-8') as f:
                return set(_json.load(f).get('properties', {}))
        except (OSError, ValueError):
            continue
    return set()


def compute_effective_config(
    env_snapshot: dict[str, str] | None = None,
    profile_name: str | None = None,
) -> list[dict[str, str]]:
    """Compute the effective configuration with provenance.

    Args:
        env_snapshot: Pre-captured environment variables. If None, uses
            os.environ directly.
        profile_name: Security profile name. If None, reads from env.

    Returns:
        List of dicts with keys: name, value, source.
        Sources: 'env', '.env', 'profile', 'platform-default',
                 'hardcoded-default', 'security-policy', 'not-set'.
    """
    if env_snapshot is None:
        env_snapshot = dict(os.environ)

    if profile_name is None:
        profile_name = _resolve_profile_name(env_snapshot)

    # Load .env file values (without overriding existing env vars).
    env_file_values = _load_env_file_values()

    profile_values = _get_profile_values(profile_name)
    platform_defaults = _get_platform_defaults()
    hardcoded_defaults = _get_hardcoded_defaults()

    # Collect all known variable names.
    all_vars: set = set()
    all_vars.update(env_snapshot.keys())
    all_vars.update(env_file_values.keys())
    all_vars.update(profile_values.keys())
    all_vars.update(platform_defaults.keys())
    all_vars.update(hardcoded_defaults.keys())
    all_vars.update(LOCKED_VARS.keys())
    # Service bind hosts are always meaningful (they fall back to
    # BIND_HOST at runtime) — list them even when no source sets them.
    all_vars.update(_SERVICE_HOST_VARS)
    # Include every var the runtime can lock so locked entries appear
    # in the report even when no source defines them.
    for _p in ('public-hardened', 'private-overlay', 'trusted-lan'):
        all_vars.update(_locked_vars_for_profile(_p).keys())

    # Filter out non-config env vars (PATH, HOME, etc.).
    config_prefixes = (
        'VNC_', 'NOVNC_', 'TTYD_', 'LANDING_', 'HEALTH_', 'BIND_',
        'SECURITY_', 'TLS_', 'DISABLE_', 'SSL_', 'MFA_', 'TOTP_',
        'AUTH_', 'SESSION_', 'ALLOWED_', 'DUCK_', 'NGINX_', 'BACKEND_',
        'PUBLIC_', 'AUDIO_', 'GAMEPAD_', 'KEEP_',
        'FLASK_', 'RECOVERY_', 'SHOW_', 'LOG_', 'WEBTERM_',
        'USER_UI_', 'HEALTHCHECK_', 'VNC_REMOTE_',
        'ALERTS_', 'ALERT_',
        'TEMP_', 'DISCORD_', 'FAIL2BAN_', 'CSP_', 'TRUSTED_',
        'SHARED_STATE_', 'ULTRAVNC_',
    )
    # Unprefixed variables that are still configuration.
    explicit_vars = {'EMAIL', 'SERVE_NOVNC_HOST'}
    all_vars = {
        v for v in all_vars
        if any(v.startswith(p) for p in config_prefixes)
        or v in LOCKED_VARS
        or v in explicit_vars
    }

    # Sort for deterministic output.
    sorted_vars = sorted(all_vars)

    result: list[dict[str, str]] = []
    for var in sorted_vars:
        value, source = _resolve_var(
            var, env_snapshot, env_file_values, profile_values,
            platform_defaults, hardcoded_defaults, profile_name,
        )
        result.append({
            'name': var,
            'value': _redact_value(var, value),
            'source': source,
        })

    return result


def _resolve_var(
    var: str,
    env_snapshot: dict[str, str],
    env_file_values: dict[str, str],
    profile_values: dict[str, str],
    platform_defaults: dict[str, str],
    hardcoded_defaults: dict[str, str],
    profile_name: str,
) -> tuple[str, str]:
    """Resolve a single variable to its effective value and source."""
    locked = _locked_vars_for_profile(profile_name)

    # 1. Environment variable (highest priority).
    env_val = env_snapshot.get(var, '')
    if env_val:
        # Check if this var is locked by security policy.
        if var in locked and env_val != locked[var]:
            return locked[var], 'security-policy (override blocked)'
        return env_val, 'env'

    # 2. .env file.
    file_val = env_file_values.get(var, '')
    if file_val:
        if var in locked and file_val != locked[var]:
            return locked[var], 'security-policy (override blocked)'
        return file_val, '.env'

    # 3. Security profile.
    profile_val = profile_values.get(var, '')
    if profile_val:
        return profile_val, f'profile:{profile_name}'

    # 4. Platform default.
    plat_val = platform_defaults.get(var, '')
    if plat_val:
        return plat_val, 'platform-default'

    # 5. Hardcoded default.
    hc_val = hardcoded_defaults.get(var, '')
    if hc_val:
        return str(hc_val), 'hardcoded-default'

    # 5b. Service bind hosts fall back to the effective BIND_HOST —
    # same chain ``config._env_host`` applies at runtime.
    if var in _SERVICE_HOST_VARS:
        bh_val, bh_src = _resolve_var(
            'BIND_HOST', env_snapshot, env_file_values, profile_values,
            platform_defaults, hardcoded_defaults, profile_name)
        if bh_val:
            return bh_val, f'fallback:BIND_HOST ({bh_src})'
        return DEFAULT_BIND_HOST, 'hardcoded-default'

    # 6. Not set.
    return '', 'not-set'


def _check_tls_required(effective_dict, profile_name, findings):
    """Require TLS in non-development profiles.

    Uses the same precedence as config._is_tls_enabled_env: an explicit
    DISABLE_SSL=true kills TLS even when TLS_ENABLED=true — reading only
    TLS_ENABLED would certify a deployment whose runtime TLS is off.
    """
    disable_ssl = effective_dict.get('DISABLE_SSL', '').strip().lower()
    tls_enabled = effective_dict.get('TLS_ENABLED', 'true')
    tls_off = (disable_ssl in ('true', '1', 'yes')
               or tls_enabled.lower() not in ('true', '1', 'yes'))
    if profile_name in ('public-hardened', 'private-overlay', 'trusted-lan') and tls_off:
        findings.append({
            'severity': 'critical',
            'message': f'TLS disabled (TLS_ENABLED={tls_enabled}, '
                       f'DISABLE_SSL={disable_ssl or "unset"}) in profile '
                       f'{profile_name} — TLS required',
        })


def _check_vnc_password(env_snapshot, findings):
    """Require a non-empty, non-weak VNC password.

    The runtime auto-generates and persists a credential to
    <run_dir>/generated_credentials.env when the env var is unset — that
    persisted value counts (same fallback check_terminal_auth uses), or
    a deployment relying on the generated password would report a false
    critical.
    """
    vnc_pass = env_snapshot.get('VNC_PASSWORD', '').strip()
    if not vnc_pass:
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )
            vnc_pass = _load_generated_credential('VNC_PASSWORD')
        except Exception:  # noqa: BLE001 — fallback is best-effort
            pass
    if not vnc_pass:
        findings.append({
            'severity': 'critical',
            'message': 'VNC_PASSWORD is empty — VNC server will reject connections',
        })
        return
    weak_lower = {p.lower() for p in WEAK_PASSWORDS}
    if vnc_pass.lower() in weak_lower:
        findings.append({
            'severity': 'critical',
            'message': 'VNC_PASSWORD is a known weak password',
        })


def _check_port_vars(env_snapshot, findings):
    """Require numeric env vars to parse and be in port range.

    Catches values like VNC_PORT=abc or NOVNC_PORT=99999 that would
    crash ``get_config()`` at runtime.
    """
    port_vars = (
        'VNC_PORT', 'VNC_HTTP_PORT', 'NOVNC_PORT', 'TTYD_PORT',
        'HEALTH_WEB_PORT', 'LANDING_PORT', 'USER_UI_PORT',
        'AUDIO_STREAM_PORT', 'GAMEPAD_PORT',
        'NGINX_HTTP_PORT', 'NGINX_HTTPS_PORT',
    )
    for var in port_vars:
        raw = env_snapshot.get(var)
        if raw is None or raw == '':
            continue
        try:
            val = int(raw)
        except (ValueError, TypeError):
            findings.append({
                'severity': 'critical',
                'message': f'{var}={raw!r} is not a valid integer',
            })
            continue
        if val < 1 or val > 65535:
            findings.append({
                'severity': 'critical',
                'message': f'{var}={val} is out of valid port range (1-65535)',
            })


def _check_tigervnc_port_mismatch(env_snapshot, findings):
    """Warn when VNC_PORT disagrees with the TigerVNC display-derived port.

    On Linux TigerVNC derives its RFB port from the display number
    (5900 + N) — the adapter launches ``vncserver :N`` and ignores
    VNC_PORT for binding, and all probes (doctor, status_all, landing,
    websockify) use the derived port. A mismatched VNC_PORT is inert but
    misleading. Windows uses VNC_PORT directly (UltraVNC PortNumber), so
    the check only applies off-Windows.
    """
    try:
        from vnc_remote_secure.platform.detection import is_windows
        if is_windows():
            return
        raw_display = (env_snapshot.get('VNC_DISPLAY', ':1') or ':1')
        display_num = int(str(raw_display).lstrip(':'))
        vnc_port_raw = env_snapshot.get('VNC_PORT', '').strip()
        if not vnc_port_raw:
            return
        vnc_port = int(vnc_port_raw)
        expected = TIGERVNC_BASE_PORT + display_num
        if vnc_port != expected:
            findings.append({
                'severity': 'warning',
                'message': (
                    f'VNC_PORT={vnc_port} is ignored on Linux — '
                    f'TigerVNC binds {TIGERVNC_BASE_PORT}+display '
                    f'({expected} for display {raw_display}); '
                    f'set VNC_PORT={expected} or '
                    f'VNC_DISPLAY=:{vnc_port - TIGERVNC_BASE_PORT} '
                    'to silence this warning.'
                ),
            })
    except (ValueError, TypeError):
        pass


def validate_config(
    env_snapshot: dict[str, str] | None = None,
    profile_name: str | None = None,
) -> list[dict[str, str]]:
    """Validate the effective configuration for contradictions.

    Returns:
        List of finding dicts with 'severity' and 'message'.
    """
    if env_snapshot is None:
        env_snapshot = dict(os.environ)
    if profile_name is None:
        profile_name = _resolve_profile_name(env_snapshot)

    findings: list[dict[str, str]] = []
    effective = compute_effective_config(env_snapshot, profile_name)
    effective_dict = {e['name']: e['value'] for e in effective}

    # Unknown keys in .env: a typo like VNC_PASWORD silently does
    # nothing while the operator believes a credential is set. Only
    # file keys are checked — os.environ holds hundreds of unrelated
    # system variables that must not be flagged.
    known = _schema_known_vars()
    if known:
        for key in sorted(set(_load_env_file_values()) - known):
            findings.append({
                'severity': 'warning',
                'message': f'Unknown config key in .env: {key} — '
                           'not declared in the schema (typo?)',
            })

    # BACKEND_BIND_HOST must be 127.0.0.1 in all profiles.
    backend_bind = effective_dict.get('BACKEND_BIND_HOST', '127.0.0.1')
    if backend_bind != '127.0.0.1':
        findings.append({
            'severity': 'critical',
            'message': f'BACKEND_BIND_HOST={backend_bind} — must be 127.0.0.1 (Zero Trust)',
        })

    _check_tls_required(effective_dict, profile_name, findings)

    # MFA required in public-hardened and private-overlay.
    mfa_required = effective_dict.get('MFA_REQUIRED', 'false')
    if (profile_name in ('public-hardened', 'private-overlay')
            and mfa_required.lower() not in ('true', '1', 'yes')):
        findings.append({
            'severity': 'critical',
            'message': f'MFA_REQUIRED={mfa_required} in profile {profile_name} — MFA required',
        })

    # nginx enabled in non-development profiles.
    nginx_enabled = effective_dict.get('NGINX_ENABLED', 'false')
    if (profile_name in ('public-hardened', 'private-overlay', 'trusted-lan')
            and nginx_enabled.lower() not in ('true', '1', 'yes')):
        findings.append({
            'severity': 'critical',
            'message': f'NGINX_ENABLED={nginx_enabled} in profile {profile_name} — reverse proxy required',
        })

    # FLASK_SECRET_KEY set in non-development profiles. The persisted
    # auth_secret.key fallback only applies in development —
    # web/application.py raises RuntimeError on hardened profiles when
    # the env var is missing, so the critical here matches the startup
    # blocker (and doctor's secrets.flask_key, which treats the
    # persisted file as 'Set' for dev-mode state).
    flask_secret = env_snapshot.get('FLASK_SECRET_KEY', '').strip()
    if (profile_name in ('public-hardened', 'private-overlay', 'trusted-lan')
            and not flask_secret):
        findings.append({
            'severity': 'critical',
            'message': 'FLASK_SECRET_KEY not set — sessions invalidated on restart',
        })

    _check_vnc_password(env_snapshot, findings)
    _check_port_vars(env_snapshot, findings)
    _check_tigervnc_port_mismatch(env_snapshot, findings)

    return findings


def diff_configs(
    config_a: list[dict[str, str]],
    config_b: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Diff two effective configs.

    Args:
        config_a: First config (from compute_effective_config).
        config_b: Second config.

    Returns:
        List of diffs with keys: name, value_a, value_b, source_a, source_b.
        Only includes variables that differ.
    """
    dict_a = {e['name']: e for e in config_a}
    dict_b = {e['name']: e for e in config_b}
    all_names = sorted(set(dict_a.keys()) | set(dict_b.keys()))
    diffs = []
    for name in all_names:
        a = dict_a.get(name, {'value': '', 'source': 'not-set'})
        b = dict_b.get(name, {'value': '', 'source': 'not-set'})
        if a['value'] != b['value']:
            diffs.append({
                'name': name,
                'value_a': a['value'],
                'source_a': a['source'],
                'value_b': b['value'],
                'source_b': b['source'],
            })
    return diffs
