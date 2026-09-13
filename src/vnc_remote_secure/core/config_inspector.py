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
import os
from typing import Dict, List, Optional, Tuple

from vnc_remote_secure.core.constants import (
    DEFAULT_BIND_HOST,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
    DEFAULT_VNC_PORT,
)
from vnc_remote_secure.security.profiles import _PROFILE_ALIASES, PROFILES

# Variables that are credentials (redacted in output).
CREDENTIAL_VARS = {
    'VNC_PASSWORD', 'TTYD_PASSWD', 'AUTH_SECRET', 'FLASK_SECRET_KEY',
    'TOTP_SECRET', 'HEALTH_AUTH_TOKEN', 'DUCKDNS_TOKEN',
    'RECOVERY_CODES_HASHES', 'TEMP_USER_PASS',
}

# Security-critical variables that cannot be overridden in hardened profiles.
LOCKED_VARS = {
    'BACKEND_BIND_HOST': '127.0.0.1',
}


def _get_platform_defaults() -> Dict[str, str]:
    """Return platform-specific default values."""
    if os.name == 'nt':
        return {
            'VNC_PORT': '5900',
            'HEALTH_WEB_PORT': '8090',
            'VNC_SERVER': 'ultravnc',
            'WEBTERM_SHELL': 'cmd.exe',
        }
    return {
        'VNC_PORT': '5901',
        'HEALTH_WEB_PORT': '8080',
        'VNC_SERVER': 'tigervncserver',
        'WEBTERM_SHELL': 'bash',
    }


def _get_hardcoded_defaults() -> Dict[str, str]:
    """Return hardcoded default values from constants."""
    return {
        'BIND_HOST': DEFAULT_BIND_HOST,
        'NOVNC_PORT': str(DEFAULT_NOVNC_PORT),
        'TTYD_PORT': str(DEFAULT_TTYD_PORT),
        'LANDING_PORT': str(DEFAULT_LANDING_PORT),
        'HEALTH_WEB_PORT': str(DEFAULT_HEALTH_PORT),
        'VNC_PORT': str(DEFAULT_VNC_PORT),
    }


def _get_profile_values(profile_name: str) -> Dict[str, str]:
    """Return the values set by a security profile."""
    resolved = _PROFILE_ALIASES.get(profile_name, profile_name)
    profile = PROFILES.get(resolved, {})
    return {k: str(v) for k, v in profile.items() if k != 'description'}


def _redact_value(name: str, value: str) -> str:
    """Redact credential values."""
    if name in CREDENTIAL_VARS and value:
        return f'[REDACTED:{len(value)}chars]'
    return value


def compute_effective_config(
    env_snapshot: Optional[Dict[str, str]] = None,
    profile_name: Optional[str] = None,
) -> List[Dict[str, str]]:
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
        profile_name = env_snapshot.get('SECURITY_PROFILE', 'development')

    # Load .env file values (without overriding existing env vars).
    env_file_values: Dict[str, str] = {}
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    env_path = os.path.join(project_root, '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
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
        except Exception:
            pass

    profile_values = _get_profile_values(profile_name)
    platform_defaults = _get_platform_defaults()
    hardcoded_defaults = _get_hardcoded_defaults()

    # Collect all known variable names.
    all_vars = set()
    all_vars.update(env_snapshot.keys())
    all_vars.update(env_file_values.keys())
    all_vars.update(profile_values.keys())
    all_vars.update(platform_defaults.keys())
    all_vars.update(hardcoded_defaults.keys())
    all_vars.update(LOCKED_VARS.keys())

    # Filter out non-config env vars (PATH, HOME, etc.).
    config_prefixes = (
        'VNC_', 'NOVNC_', 'TTYD_', 'LANDING_', 'HEALTH_', 'BIND_',
        'SECURITY_', 'TLS_', 'DISABLE_', 'SSL_', 'MFA_', 'TOTP_',
        'AUTH_', 'SESSION_', 'ALLOWED_', 'DUCK_', 'NGINX_', 'BACKEND_',
        'PUBLIC_', 'RECORDING_', 'AUDIO_', 'GAMEPAD_', 'KEEP_',
        'FLASK_', 'RECOVERY_', 'SHOW_', 'LOG_', 'WEBTERM_',
        'USER_UI_', 'HEALTHCHECK_', 'VNC_REMOTE_',
    )
    all_vars = {
        v for v in all_vars
        if any(v.startswith(p) for p in config_prefixes) or v in LOCKED_VARS
    }

    # Sort for deterministic output.
    all_vars = sorted(all_vars)

    result: List[Dict[str, str]] = []
    for var in all_vars:
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
    env_snapshot: Dict[str, str],
    env_file_values: Dict[str, str],
    profile_values: Dict[str, str],
    platform_defaults: Dict[str, str],
    hardcoded_defaults: Dict[str, str],
    profile_name: str,
) -> Tuple[str, str]:
    """Resolve a single variable to its effective value and source."""
    # 1. Environment variable (highest priority).
    env_val = env_snapshot.get(var, '')
    if env_val:
        # Check if this var is locked by security policy.
        if var in LOCKED_VARS and profile_name in ('public-hardened', 'private-overlay'):
            locked_val = LOCKED_VARS[var]
            if env_val != locked_val:
                return locked_val, 'security-policy (override blocked)'
        return env_val, 'env'

    # 2. .env file.
    file_val = env_file_values.get(var, '')
    if file_val:
        if var in LOCKED_VARS and profile_name in ('public-hardened', 'private-overlay'):
            locked_val = LOCKED_VARS[var]
            if file_val != locked_val:
                return locked_val, 'security-policy (override blocked)'
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

    # 6. Not set.
    return '', 'not-set'


def validate_config(
    env_snapshot: Optional[Dict[str, str]] = None,
    profile_name: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Validate the effective configuration for contradictions.

    Returns:
        List of finding dicts with 'severity' and 'message'.
    """
    if env_snapshot is None:
        env_snapshot = dict(os.environ)
    if profile_name is None:
        profile_name = env_snapshot.get('SECURITY_PROFILE', 'development')

    findings: List[Dict[str, str]] = []
    effective = compute_effective_config(env_snapshot, profile_name)
    effective_dict = {e['name']: e['value'] for e in effective}

    # Check: BACKEND_BIND_HOST must be 127.0.0.1 in all profiles.
    backend_bind = effective_dict.get('BACKEND_BIND_HOST', '127.0.0.1')
    if backend_bind != '127.0.0.1':
        findings.append({
            'severity': 'critical',
            'message': f'BACKEND_BIND_HOST={backend_bind} — must be 127.0.0.1 (Zero Trust)',
        })

    # Check: TLS must be enabled in non-development profiles.
    tls_enabled = effective_dict.get('TLS_ENABLED', 'true')
    if profile_name in ('public-hardened', 'private-overlay', 'trusted-lan'):
        if tls_enabled.lower() not in ('true', '1', 'yes'):
            findings.append({
                'severity': 'critical',
                'message': f'TLS_ENABLED={tls_enabled} in profile {profile_name} — TLS required',
            })

    # Check: MFA required in public-hardened and private-overlay.
    mfa_required = effective_dict.get('MFA_REQUIRED', 'false')
    if profile_name in ('public-hardened', 'private-overlay'):
        if mfa_required.lower() not in ('true', '1', 'yes'):
            findings.append({
                'severity': 'critical',
                'message': f'MFA_REQUIRED={mfa_required} in profile {profile_name} — MFA required',
            })

    # Check: nginx enabled in non-development profiles.
    nginx_enabled = effective_dict.get('NGINX_ENABLED', 'false')
    if profile_name in ('public-hardened', 'private-overlay', 'trusted-lan'):
        if nginx_enabled.lower() not in ('true', '1', 'yes'):
            findings.append({
                'severity': 'critical',
                'message': f'NGINX_ENABLED={nginx_enabled} in profile {profile_name} — reverse proxy required',
            })

    # Check: FLASK_SECRET_KEY set in non-development profiles.
    flask_secret = env_snapshot.get('FLASK_SECRET_KEY', '').strip()
    if profile_name in ('public-hardened', 'private-overlay', 'trusted-lan'):
        if not flask_secret:
            findings.append({
                'severity': 'critical',
                'message': 'FLASK_SECRET_KEY not set — sessions invalidated on restart',
            })

    # Check: VNC_PASSWORD not empty.
    vnc_pass = env_snapshot.get('VNC_PASSWORD', '').strip()
    if not vnc_pass:
        findings.append({
            'severity': 'critical',
            'message': 'VNC_PASSWORD is empty — VNC server will reject connections',
        })

    # Check: VNC_PASSWORD not a default/weak password.
    weak_passwords = {'changeme', 'admin123', 'password', 'YourStrongPassword123', '123456'}
    if vnc_pass.lower() in weak_passwords:
        findings.append({
            'severity': 'critical',
            'message': 'VNC_PASSWORD is a known weak password',
        })

    return findings


def diff_configs(
    config_a: List[Dict[str, str]],
    config_b: List[Dict[str, str]],
) -> List[Dict[str, str]]:
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
