"""Security posture scoring for VNC Remote Secure.

Calculates a local security score (0-100) based on configuration,
exposure, authentication, and operational settings. Designed for
display in the operational dashboard.
"""
import logging
import os
from typing import List

from vnc_remote_secure.core.config import load_env_file

logger = logging.getLogger(__name__)


def _env_bool(name: str, default: str = 'false') -> bool:
    return os.environ.get(name, default).lower() in ('true', '1', 'yes')


def _env_val(name: str, default: str = '') -> str:
    return os.environ.get(name, default)


def _is_tls_enabled() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    Bash uses DISABLE_SSL (negative logic); Python uses TLS_ENABLED
    (positive logic). This function reads both so a single .env file
    works across both layers.
    """
    tls_val = os.environ.get('TLS_ENABLED', '').strip()
    if tls_val:
        return tls_val.lower() in ('true', '1', 'yes')
    disable_val = os.environ.get('DISABLE_SSL', '').strip()
    if disable_val:
        return disable_val.lower() not in ('true', '1', 'yes')
    return True  # default: TLS enabled


def calculate_posture() -> dict:
    """Calculate the security posture score and individual checks.

    Returns a dict with:
        - ``score``: 0-100
        - ``checks``: list of {name, status, detail}
        - ``summary``: short text summary
        - ``deployment_decision``: 'allowed' or 'blocked'
        - ``blocking_findings``: list of critical findings that block deployment
    """
    load_env_file()
    checks: List[dict] = []
    score = 100

    def add(name, ok, warn_msg='', fail_msg='', points=10):
        nonlocal score
        if ok:
            checks.append({'name': name, 'status': 'ok', 'detail': ''})
        elif warn_msg:
            checks.append({'name': name, 'status': 'warn', 'detail': warn_msg})
            score -= points // 2
        else:
            checks.append({'name': name, 'status': 'fail', 'detail': fail_msg})
            score -= points

    # TLS / HTTPS (unified: reads TLS_ENABLED or DISABLE_SSL)
    tls = _is_tls_enabled()
    add(
        'HTTPS/TLS enabled',
        tls,
        warn_msg='TLS disabled — traffic is unencrypted',
        fail_msg='TLS disabled — all traffic is unencrypted',
        points=15,
    )

    # Bind to localhost
    bind = _env_val('BIND_HOST', '127.0.0.1')
    add(
        'Services bound to localhost',
        bind == '127.0.0.1',
        warn_msg=f'Services bind to {bind} (exposed to network)',
        points=10,
    )

    # MFA
    mfa = _env_bool('MFA_REQUIRED', 'false') or bool(_env_val('TOTP_SECRET'))
    add(
        'MFA enabled',
        mfa,
        warn_msg='MFA not configured — single-factor auth only',
        points=10,
    )

    # nginx reverse proxy
    nginx = _env_bool('NGINX_ENABLED', 'false')
    add(
        'Reverse proxy (nginx) enabled',
        nginx,
        warn_msg='No reverse proxy — services exposed directly',
        points=5,
    )

    # Health auth
    health_auth = bool(_env_val('HEALTH_AUTH_TOKEN'))
    add(
        'Health endpoint protected',
        health_auth,
        warn_msg='Health endpoint has no auth token',
        points=5,
    )

    # Strong passwords (check if TTYD_PASSWD is set and not weak)
    ttyd_pass = _env_val('TTYD_PASSWD')
    has_strong = (
        ttyd_pass
        and len(ttyd_pass) >= 8
        and any(c.isupper() for c in ttyd_pass)
        and any(c.islower() for c in ttyd_pass)
        and any(c.isdigit() for c in ttyd_pass)
    )
    add(
        'Strong credentials configured',
        bool(has_strong),
        warn_msg='Credentials may be weak or missing',
        fail_msg='No credentials configured',
        points=10,
    )

    # Temp user cleanup
    keep_user = _env_bool('KEEP_TEMP_USER', 'false')
    add(
        'Temp user removed on exit',
        not keep_user,
        warn_msg='KEEP_TEMP_USER=true — temp user persists after exit',
        points=5,
    )

    # SSL certificate
    cert = _env_val('SSL_CERT', '')
    key = _env_val('SSL_KEY', '')
    add(
        'SSL certificate configured',
        bool(cert and key) or not tls,
        warn_msg='No SSL certificate path configured',
        points=5,
    )

    # DuckDNS / domain
    domain = _env_val('DUCK_DOMAIN', '')
    add(
        'Domain configured (DuckDNS)',
        bool(domain),
        warn_msg='No domain configured — local access only',
        points=5,
    )

    # Discord webhook (should not have placeholder)
    webhook = _env_val('DISCORD_WEBHOOK_URL', '')
    add(
        'No placeholder secrets',
        'YOUR_WEBHOOK_URL' not in webhook,
        warn_msg='Placeholder value in DISCORD_WEBHOOK_URL',
        points=5,
    )

    # Session timeout
    try:
        idle = int(_env_val('SESSION_IDLE_TIMEOUT', '900'))
        add(
            'Session idle timeout configured',
            idle <= 1800,
            warn_msg=f'Session idle timeout is {idle}s (consider ≤1800s)',
            points=5,
    )
    except (ValueError, TypeError):
        checks.append({'name': 'Session idle timeout', 'status': 'warn', 'detail': 'Not configured'})

    # Rate limiting
    max_attempts = _env_val('AUTH_MAX_ATTEMPTS', '5')
    add(
        'Rate limiting configured',
        bool(max_attempts),
        warn_msg='No rate limiting configured',
        points=5,
    )

    score = max(0, min(100, score))
    summary = _summarize(score)

    # Blocking findings from profiles (hard blockers, not just score deductions)
    from vnc_remote_secure.security.profiles import get_blocking_findings
    blocking = get_blocking_findings()
    decision = 'blocked' if blocking else 'allowed'

    return {
        'score': score,
        'checks': checks,
        'summary': summary,
        'deployment_decision': decision,
        'blocking_findings': blocking,
    }


def _summarize(score: int) -> str:
    if score >= 90:
        return 'Excellent security posture'
    if score >= 75:
        return 'Good security posture with minor gaps'
    if score >= 50:
        return 'Moderate security posture — several improvements needed'
    return 'Poor security posture — immediate action required'
