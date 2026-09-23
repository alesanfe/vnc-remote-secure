"""Security posture scoring for VNC Remote Secure.

Calculates a local security score (0-100) based on configuration,
exposure, authentication, and operational settings. Designed for
display in the operational dashboard.
"""
import logging
import os

from vnc_remote_secure.core.config import env_flag, load_env_file

logger = logging.getLogger(__name__)


def _env_val(name: str, default: str = '') -> str:
    return os.environ.get(name, default)


def _is_tls_enabled() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    Delegates to the canonical resolver (``config._is_tls_enabled_env``)
    — keeping a local interpretation here would diverge from the
    runtime: an explicit ``DISABLE_SSL=true`` is a kill-switch that
    wins over ``TLS_ENABLED``, while this copy checked TLS_ENABLED
    first and reported the opposite of what services actually do.
    """
    from vnc_remote_secure.core.config import _is_tls_enabled_env
    return _is_tls_enabled_env()


def _add_finding(findings, name, ok, warn_msg='', fail_msg='', points=10):
    """Append a posture finding to the findings list.

    A finding records its name, status (ok/warn/fail), detail text, and
    the point value used to compute the final score. Status is 'ok' when
    ``ok`` is true, 'warn' when a ``warn_msg`` is provided, otherwise 'fail'.
    """
    if ok:
        findings.append({'name': name, 'status': 'ok', 'detail': '', 'points': points})
    elif warn_msg:
        findings.append({'name': name, 'status': 'warn', 'detail': warn_msg, 'points': points})
    else:
        findings.append({'name': name, 'status': 'fail', 'detail': fail_msg, 'points': points})


def _check_tls_posture(findings):
    """Add findings about TLS/HTTPS and SSL certificate configuration."""
    # TLS / HTTPS (unified: reads TLS_ENABLED or DISABLE_SSL)
    tls = _is_tls_enabled()
    _add_finding(
        findings,
        'HTTPS/TLS enabled',
        tls,
        warn_msg='TLS disabled — traffic is unencrypted',
        fail_msg='TLS disabled — all traffic is unencrypted',
        points=15,
    )

    # SSL certificate: the services resolve a cert/key pair via
    # create_ssl_context() — explicit SSL_CERT/SSL_KEY env vars OR the
    # canonical ssl dir (get_ssl_dir()/fullchain.pem+privkey.pem).
    # Checking only the env vars reports "not configured" on
    # deployments that are in fact serving TLS.
    cert = _env_val('SSL_CERT', '')
    key = _env_val('SSL_KEY', '')
    if not (cert and key):
        try:
            from vnc_remote_secure.core.paths import get_ssl_dir
            ssl_dir = get_ssl_dir()
            d_cert = os.path.join(ssl_dir, 'fullchain.pem')
            d_key = os.path.join(ssl_dir, 'privkey.pem')
            if os.path.isfile(d_cert) and os.path.isfile(d_key):
                cert, key = d_cert, d_key
        except Exception:  # noqa: BLE001
            pass
    # When TLS is enabled, a cert/key pair must be configured. When TLS
    # is disabled, mark as warning (not OK) so the posture reflects the
    # missing transport security rather than hiding it.
    _add_finding(
        findings,
        'SSL certificate configured',
        bool(tls and cert and key),
        warn_msg='TLS disabled or no SSL certificate path configured',
        points=5,
    )


def _check_auth_posture(findings):
    """Add findings about authentication (MFA, rate limit, passwords, secrets)."""
    # MFA
    mfa = env_flag('MFA_REQUIRED', 'false') or bool(_env_val('TOTP_SECRET'))
    _add_finding(
        findings,
        'MFA enabled',
        mfa,
        warn_msg='MFA not configured — single-factor auth only',
        points=10,
    )

    # Strong passwords: validate all configured credentials, not just TTYD.
    def _is_strong(p):
        return (
            p and len(p) >= 8
            and any(c.isupper() for c in p)
            and any(c.islower() for c in p)
            and any(c.isdigit() for c in p)
        )

    def _cred(name):
        value = _env_val(name)
        if not value:
            # Auto-generated credentials persist to
            # generated_credentials.env — a posture check that only
            # reads os.environ reports "no credentials" on deployments
            # whose secrets were generated, not user-set.
            try:
                from vnc_remote_secure.core.config import (
                    _load_generated_credential,
                )
                value = _load_generated_credential(name)
            except Exception:  # noqa: BLE001 - fallback is best-effort
                value = ''
        return value

    creds = [
        _cred('TTYD_PASSWD'),
        _cred('USER_UI_PASSWORD'),
        _cred('LANDING_PASSWORD'),
        _cred('VNC_PASSWORD'),
    ]
    has_strong = all(_is_strong(p) for p in creds if p) and any(creds)
    _add_finding(
        findings,
        'Strong credentials configured',
        bool(has_strong),
        warn_msg='Credentials may be weak or missing',
        fail_msg='No credentials configured',
        points=10,
    )

    # Rate limiting
    max_attempts = _env_val('AUTH_MAX_ATTEMPTS', '5')
    _add_finding(
        findings,
        'Rate limiting configured',
        bool(max_attempts),
        warn_msg='No rate limiting configured',
        points=5,
    )

    # Persistent session secret (FLASK_SECRET_KEY)
    flask_secret = _env_val('FLASK_SECRET_KEY', '')
    from vnc_remote_secure.security.profiles import resolve_profile
    profile = resolve_profile()
    if profile in ('public-hardened', 'private-overlay', 'trusted-lan'):
        _add_finding(
            findings,
            'Persistent session secret (FLASK_SECRET_KEY)',
            bool(flask_secret),
            warn_msg='FLASK_SECRET_KEY not set — sessions invalidated on restart',
            points=5,
        )
    else:
        # In development, ephemeral secret is acceptable.
        findings.append({
            'name': 'Persistent session secret (FLASK_SECRET_KEY)',
            'status': 'ok',
            'detail': 'Development profile — ephemeral secret acceptable',
            'points': 0,
        })

    # Health auth - required when ANY health-serving bind is
    # public. The endpoints live on the standalone health server
    # and the Flask UI alike, so HEALTH_WEB_HOST, USER_UI_HOST
    # and BIND_HOST are all considered - mirroring check_health_auth.
    health_auth = bool(_env_val('HEALTH_AUTH_TOKEN'))
    base_bind = _env_val('BIND_HOST', '127.0.0.1')
    health_public = any(
        h not in ('127.0.0.1', 'localhost', '::1')
        for h in (
            _env_val('HEALTH_WEB_HOST', '') or base_bind,
            _env_val('USER_UI_HOST', '') or base_bind,
        ))
    _add_finding(
        findings,
        'Health endpoint protected',
        health_auth or not health_public,
        warn_msg=(
            'Health endpoint has no auth token'
            if health_public else
            'Health endpoint has no auth token (loopback-only — '
            'acceptable but set HEALTH_AUTH_TOKEN before exposing)'),
        points=5 if health_public else 0,
    )

    # Discord webhook (should not have placeholder)
    webhook = _env_val('DISCORD_WEBHOOK_URL', '')
    _add_finding(
        findings,
        'No placeholder secrets',
        'YOUR_WEBHOOK_URL' not in webhook,
        warn_msg='Placeholder value in DISCORD_WEBHOOK_URL',
        points=5,
    )


def _check_network_posture(findings):
    """Add findings about network exposure (bind host, nginx, domain)."""
    # Bind to localhost
    bind = _env_val('BIND_HOST', '127.0.0.1')
    _add_finding(
        findings,
        'Services bound to localhost',
        bind == '127.0.0.1',
        warn_msg=f'Services bind to {bind} (exposed to network)',
        points=10,
    )

    # nginx reverse proxy
    nginx = env_flag('NGINX_ENABLED', 'false')
    _add_finding(
        findings,
        'Reverse proxy (nginx) enabled',
        nginx,
        warn_msg='No reverse proxy — services exposed directly',
        points=5,
    )

    # DuckDNS / domain
    domain = _env_val('DUCK_DOMAIN', '')
    _add_finding(
        findings,
        'Domain configured (DuckDNS)',
        bool(domain),
        warn_msg='No domain configured — local access only',
        points=5,
    )


def _check_session_posture(findings):
    """Add findings about session timeouts."""
    # Session timeout
    try:
        from vnc_remote_secure.core.constants import DEFAULT_SESSION_IDLE_TIMEOUT
        idle = int(_env_val('SESSION_IDLE_TIMEOUT', str(DEFAULT_SESSION_IDLE_TIMEOUT)))
        _add_finding(
            findings,
            'Session idle timeout configured',
            idle <= 1800,
            warn_msg=f'Session idle timeout is {idle}s (consider ≤1800s)',
            points=5,
        )
    except (ValueError, TypeError):
        findings.append({'name': 'Session idle timeout', 'status': 'warn', 'detail': 'Not configured', 'points': 0})


def _check_temp_user_posture(findings):
    """Add findings about temp user cleanup."""
    # Temp user cleanup
    keep_user = env_flag('KEEP_TEMP_USER', 'false')
    _add_finding(
        findings,
        'Temp user removed on exit',
        not keep_user,
        warn_msg='KEEP_TEMP_USER=true — temp user persists after exit',
        points=5,
    )


def _check_shared_state_posture(findings):
    """Add findings about the shared-state backend.

    Rate limits, revocations and single-use claims are only
    cross-process on sqlite — a memory backend (or a degraded
    fallback) silently narrows every one of them to this process.
    """
    from vnc_remote_secure.security.shared_state import backend_degraded
    backend = _env_val('SHARED_STATE_BACKEND', 'sqlite')
    degraded = backend_degraded()
    _add_finding(
        findings,
        'Shared-state backend (cross-process auth)',
        backend == 'sqlite' and not degraded,
        warn_msg=(f'SHARED_STATE_BACKEND={backend}'
                  + (' degraded to in-memory fallback' if degraded else '')
                  + ' — revocation/single-use/rate-limit guarantees '
                  'are per-process only'),
        points=8,
    )


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
    findings: list[dict] = []

    # Run each category of checks, appending findings.
    _check_tls_posture(findings)
    _check_auth_posture(findings)
    _check_network_posture(findings)
    _check_session_posture(findings)
    _check_temp_user_posture(findings)
    _check_shared_state_posture(findings)

    # Compute the score from the collected findings.
    score = 100
    for f in findings:
        if f['status'] == 'warn':
            score -= f['points'] // 2
        elif f['status'] == 'fail':
            score -= f['points']
    score = max(0, min(100, score))
    summary = _summarize(score)

    # Checks exposed to callers exclude the internal 'points' field.
    checks = [{'name': f['name'], 'status': f['status'], 'detail': f['detail']} for f in findings]

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
