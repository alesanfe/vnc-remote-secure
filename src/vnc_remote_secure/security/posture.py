"""Security posture scoring for VNC Remote Secure.

Calculates a local security score (0-100) based on configuration,
exposure, authentication, and operational settings. Designed for
display in the operational dashboard.
"""

import logging
import os

from vnc_remote_secure.core.config import env_flag, load_env_file

logger = logging.getLogger(__name__)


def _env_val(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _is_tls_enabled() -> bool:
    """Check if TLS is enabled, unifying TLS_ENABLED and DISABLE_SSL.

    Delegates to the canonical resolver (``config._is_tls_enabled_env``)
    â€” keeping a local interpretation here would diverge from the
    runtime: an explicit ``DISABLE_SSL=true`` is a kill-switch that
    wins over ``TLS_ENABLED``, while this copy checked TLS_ENABLED
    first and reported the opposite of what services actually do.
    """
    from vnc_remote_secure.core.config import _is_tls_enabled_env

    return _is_tls_enabled_env()


def _severity(status: str, points: int) -> str:
    """Deterministic severity for a finding â€” derived from the
    status and the score weight so the UI can sort critical issues
    without a second opinion about the deduction maths."""
    if status == "ok":
        return "info"
    if status == "fail":
        return "critical" if points >= 10 else "high"
    return "high" if points >= 10 else "medium" if points >= 5 else "low"


def _add_finding(findings, name, ok, key="", warn_msg="", fail_msg="", points=10, evidence="", params=None):
    """Append a posture finding to the findings list.

    A finding records its name, status (ok/warn/fail), severity,
    detail text, observed ``evidence`` (never a secret value) and the
    point value used to compute the final score. Status is 'ok' when
    ``ok`` is true, 'warn' when a ``warn_msg`` is provided, otherwise
    'fail'. ``key`` is a stable slug the UI uses to localize
    name/detail â€” same pattern as ``summary_key``.
    """
    if ok:
        findings.append(
            {
                "name": name,
                "key": key,
                "status": "ok",
                "severity": "info",
                "detail": "", "params": params or {},
                "evidence": evidence,
                "points": points,
            }
        )
    elif warn_msg:
        findings.append(
            {
                "name": name,
                "key": key,
                "status": "warn",
                "severity": _severity("warn", points),
                "detail": warn_msg,
                "params": params or {},
                "evidence": evidence,
                "points": points,
            }
        )
    else:
        findings.append(
            {
                "name": name,
                "key": key,
                "status": "fail",
                "severity": _severity("fail", points),
                "detail": fail_msg,
                "params": params or {},
                "evidence": evidence,
                "points": points,
            }
        )


def _check_tls_posture(findings):
    """Add findings about TLS/HTTPS and SSL certificate configuration."""
    # TLS / HTTPS (unified: reads TLS_ENABLED or DISABLE_SSL)
    tls = _is_tls_enabled()
    _add_finding(
        findings,
        "HTTPS/TLS enabled",
        tls,
        key="tls",
        warn_msg="TLS disabled â€” traffic is unencrypted",
        fail_msg="TLS disabled â€” all traffic is unencrypted",
        points=15,
        evidence=f"TLS enabled={tls}",
    )

    # SSL certificate: the services resolve a cert/key pair via
    # create_ssl_context() â€” explicit SSL_CERT/SSL_KEY env vars OR the
    # canonical ssl dir (get_ssl_dir()/fullchain.pem+privkey.pem).
    # Checking only the env vars reports "not configured" on
    # deployments that are in fact serving TLS.
    cert = _env_val("SSL_CERT", "")
    key = _env_val("SSL_KEY", "")
    if not (cert and key):
        try:
            from vnc_remote_secure.core.paths import get_ssl_dir

            ssl_dir = get_ssl_dir()
            d_cert = os.path.join(ssl_dir, "fullchain.pem")
            d_key = os.path.join(ssl_dir, "privkey.pem")
            if os.path.isfile(d_cert) and os.path.isfile(d_key):
                cert, key = d_cert, d_key
        except Exception:  # noqa: BLE001
            pass
    # When TLS is enabled, a cert/key pair must be configured. When TLS
    # is disabled, mark as warning (not OK) so the posture reflects the
    # missing transport security rather than hiding it.
    _add_finding(
        findings,
        "SSL certificate configured",
        bool(tls and cert and key),
        key="ssl_cert",
        warn_msg="TLS disabled or no SSL certificate path configured",
        points=5,
        evidence="cert/key pair " + ("resolved" if cert and key else "missing"),
    )


def _check_auth_posture(findings):
    """Add findings about authentication (MFA, rate limit, passwords, secrets)."""
    _check_mfa_finding(findings)
    _check_credential_strength(findings)
    _check_rate_limit_finding(findings)
    _check_session_secret_finding(findings)
    _check_health_auth_finding(findings)
    _check_webhook_finding(findings)


def _check_mfa_finding(findings) -> None:
    mfa = env_flag("MFA_REQUIRED", "false") or bool(_env_val("TOTP_SECRET"))
    _add_finding(
        findings,
        "MFA enabled",
        mfa,
        key="mfa",
        warn_msg="MFA not configured â€” single-factor auth only",
        points=10,
        evidence=f"MFA_REQUIRED/TOTP_SECRET configured={mfa}",
    )


def _is_strong_password(p) -> bool:
    return bool(
        p
        and len(p) >= 8
        and any(c.isupper() for c in p)
        and any(c.islower() for c in p)
        and any(c.isdigit() for c in p)
    )


def _credential_value(name: str) -> str:
    """Read a credential from env, falling back to the generated-
    credentials file â€” a posture check that only reads os.environ
    reports "no credentials" on deployments whose secrets were
    generated, not user-set."""
    value = _env_val(name)
    if not value:
        try:
            from vnc_remote_secure.core.config import (
                _load_generated_credential,
            )

            value = _load_generated_credential(name)
        except Exception:  # noqa: BLE001 - fallback is best-effort
            value = ""
    return value


def _check_credential_strength(findings) -> None:
    """Strong passwords: validate all configured credentials, not just TTYD."""
    creds = [
        _credential_value("TTYD_PASSWD"),
        _credential_value("USER_UI_PASSWORD"),
        _credential_value("LANDING_PASSWORD"),
        _credential_value("VNC_PASSWORD"),
    ]
    has_strong = all(_is_strong_password(p) for p in creds if p) and any(creds)
    _add_finding(
        findings,
        "Strong credentials configured",
        bool(has_strong),
        key="strong_creds",
        warn_msg="Credentials may be weak or missing",
        fail_msg="No credentials configured",
        points=10,
        # Count only â€” credential values never become evidence.
        evidence=f"{sum(1 for c in creds if c)} credential(s) set",
    )


def _check_rate_limit_finding(findings) -> None:
    max_attempts = _env_val("AUTH_MAX_ATTEMPTS", "5")
    _add_finding(
        findings,
        "Rate limiting configured",
        bool(max_attempts),
        key="rate_limit",
        warn_msg="No rate limiting configured",
        points=5,
        evidence=f"AUTH_MAX_ATTEMPTS={max_attempts}",
    )


def _check_session_secret_finding(findings) -> None:
    """Persistent session secret (FLASK_SECRET_KEY) â€” required on
    hardened profiles; ephemeral is acceptable in development."""
    flask_secret = _env_val("FLASK_SECRET_KEY", "")
    from vnc_remote_secure.security.profiles import resolve_profile

    profile = resolve_profile()
    if profile in ("public-hardened", "private-overlay", "trusted-lan"):
        _add_finding(
            findings,
            "Persistent session secret (FLASK_SECRET_KEY)",
            bool(flask_secret),
        key="session_secret",
            warn_msg="FLASK_SECRET_KEY not set â€” sessions invalidated on restart",
            points=5,
            evidence=f"profile={profile}, secret set={bool(flask_secret)}",
        )
    else:
        findings.append(
            {
                "name": "Persistent session secret (FLASK_SECRET_KEY)",
                "status": "ok",
                "severity": "info",
                "detail": "Development profile â€” ephemeral secret acceptable",
                "evidence": f"profile={profile}",
                "points": 0,
            }
        )


def _check_health_auth_finding(findings) -> None:
    """Health auth - required when ANY health-serving bind is
    public. The endpoints are served by both the standalone health
    service and the internal user_ui health app, so
    HEALTH_WEB_HOST, USER_UI_HOST and BIND_HOST are all considered
    - mirroring check_health_auth."""
    health_auth = bool(_env_val("HEALTH_AUTH_TOKEN"))
    base_bind = _env_val("BIND_HOST", "127.0.0.1")
    health_public = any(
        h not in ("127.0.0.1", "localhost", "::1")
        for h in (
            _env_val("HEALTH_WEB_HOST", "") or base_bind,
            _env_val("USER_UI_HOST", "") or base_bind,
        )
    )
    _add_finding(
        findings,
        "Health endpoint protected",
        health_auth or not health_public,
        key="health_endpoint_pub" if health_public else "health_endpoint_priv",
        warn_msg=(
            "Health endpoint has no auth token"
            if health_public
            else "Health endpoint has no auth token (loopback-only â€” "
            "acceptable but set HEALTH_AUTH_TOKEN before exposing)"
        ),
        params={"public": health_public},
        points=5 if health_public else 0,
        evidence=(f"HEALTH_AUTH_TOKEN set={health_auth}, " f"public_bind={health_public}"),
    )


def _check_webhook_finding(findings) -> None:
    """Discord webhook (should not have a placeholder)."""
    webhook = _env_val("DISCORD_WEBHOOK_URL", "")
    _add_finding(
        findings,
        "No placeholder secrets",
        "YOUR_WEBHOOK_URL" not in webhook,
        key="no_placeholder_secrets",
        warn_msg="Placeholder value in DISCORD_WEBHOOK_URL",
        points=5,
        evidence="DISCORD_WEBHOOK_URL " + ("unset" if not webhook else "set"),
    )


def _check_network_posture(findings):
    """Add findings about network exposure (bind host, nginx, domain)."""
    # Bind to localhost
    bind = _env_val("BIND_HOST", "127.0.0.1")
    _add_finding(
        findings,
        "Services bound to localhost",
        bind == "127.0.0.1",
        key="bind_localhost",
        warn_msg=f"Services bind to {bind} (exposed to network)",
        params={"bind": bind},
        points=10,
        evidence=f"BIND_HOST={bind}",
    )

    # nginx reverse proxy
    nginx = env_flag("NGINX_ENABLED", "false")
    _add_finding(
        findings,
        "Reverse proxy (nginx) enabled",
        nginx,
        key="nginx_proxy",
        warn_msg="No reverse proxy â€” services exposed directly",
        points=5,
        evidence=f"NGINX_ENABLED={nginx}",
    )

    # DuckDNS / domain
    domain = _env_val("DUCK_DOMAIN", "")
    _add_finding(
        findings,
        "Domain configured (DuckDNS)",
        bool(domain),
        key="domain",
        warn_msg="No domain configured â€” local access only",
        points=5,
        evidence=f"DUCK_DOMAIN configured={bool(domain)}",
    )


def _check_session_posture(findings):
    """Add findings about session timeouts."""
    # Session timeout
    try:
        from vnc_remote_secure.core.constants import DEFAULT_SESSION_IDLE_TIMEOUT

        idle = int(_env_val("SESSION_IDLE_TIMEOUT", str(DEFAULT_SESSION_IDLE_TIMEOUT)))
        _add_finding(
            findings,
            "Session idle timeout configured",
            idle <= 1800,
        key="session_idle",
            warn_msg=f"Session idle timeout is {idle}s (consider <= 1800s)",
            params={"idle": idle},
            points=5,
            evidence=f"SESSION_IDLE_TIMEOUT={idle}s",
        )
    except (ValueError, TypeError):
        findings.append(
            {
                "name": "Session idle timeout",
                "key": "session_idle_unconfigured",
                "status": "warn",
                "severity": "medium",
                "detail": "Not configured",
                "evidence": "",
                "points": 0,
            }
        )


def _check_temp_user_posture(findings):
    """Add findings about temp user cleanup."""
    # Temp user cleanup
    keep_user = env_flag("KEEP_TEMP_USER", "false")
    _add_finding(
        findings,
        "Temp user removed on exit",
        not keep_user,
        key="temp_user_cleanup",
        warn_msg="KEEP_TEMP_USER=true â€” temp user persists after exit",
        points=5,
        evidence=f"KEEP_TEMP_USER={keep_user}",
    )


def _check_shared_state_posture(findings):
    """Add findings about the shared-state backend.

    Rate limits, revocations and single-use claims are only
    cross-process on sqlite â€” a memory backend (or a degraded
    fallback) silently narrows every one of them to this process.
    """
    from vnc_remote_secure.security.shared_state import backend_degraded

    backend = _env_val("SHARED_STATE_BACKEND", "sqlite")
    degraded = backend_degraded()
    _add_finding(
        findings,
        "Shared-state backend (cross-process auth)",
        backend == "sqlite" and not degraded,
        key="shared_state_degraded" if degraded else "shared_state",
        warn_msg=(
            f"SHARED_STATE_BACKEND={backend}"
            + (" degraded to in-memory fallback" if degraded else "")
            + " â€” revocation/single-use/rate-limit guarantees "
            "are per-process only"
        ),
        params={"backend": backend, "degraded": degraded},
        points=8,
        evidence=(f"SHARED_STATE_BACKEND={backend}, " f"degraded={degraded}"),
    )


def _check_attack_surface(findings):
    """Enumerate the enabled optional services â€” the plugin registry
    (core.plugins) is the declared contract; the posture is where the
    operator sees which optional surfaces are live and which
    capability each one requires."""
    try:
        import platform as _pf

        from vnc_remote_secure.core.config import get_config
        from vnc_remote_secure.core.plugins import attack_surface

        cfg = get_config()
        surface = attack_surface(cfg, _pf.system() == "Windows")
    except Exception:  # noqa: BLE001 - posture must never fail on this
        return
    enabled = sorted(surface)
    # Informational only (points=0): enabling an optional service is a
    # legitimate deployment choice â€” the finding exists so the attack
    # surface is enumerated next to the other findings, not to deduct.
    findings.append(
        {
            "name": "Optional services (attack surface)",
            "key": "attack_surface",
            "status": "ok",
            "severity": "info",
            "detail": "",
            "evidence": (
                (
                    f"{len(enabled)} enabled: "
                    + ", ".join(f"{n}({surface[n] or 'no-session-surface'})" for n in enabled)
                )
                if enabled
                else "none"
            ),
            "points": 0,
        }
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
    _check_attack_surface(findings)

    # Compute the score from the collected findings.
    score = 100
    for f in findings:
        if f["status"] == "warn":
            score -= f["points"] // 2
        elif f["status"] == "fail":
            score -= f["points"]
    score = max(0, min(100, score))
    summary_key, summary = _summarize(score)

    # Checks exposed to callers exclude the internal 'points' field;
    # severity + evidence make a critical finding self-describing in
    # the UI without reverse-engineering the score maths.
    checks = [
        {
            "name": f["name"],
            "key": f.get("key", ""),
            "status": f["status"],
            "severity": f["severity"],
            "detail": f["detail"],
            "evidence": f.get("evidence", ""),
            "params": f.get("params", {}),
        }
        for f in findings
    ]

    # Blocking findings from profiles (hard blockers, not just score deductions)
    from vnc_remote_secure.security.profiles import get_blocking_findings

    blocking = get_blocking_findings()
    decision = "blocked" if blocking else "allowed"

    return {
        "score": score,
        "checks": checks,
        "summary": summary,
        "summary_key": summary_key,
        "deployment_decision": decision,
        "blocking_findings": blocking,
    }


def _summarize(score: int) -> tuple:
    """Return ``(band_key, english_fallback)`` â€” the key lets UIs
    localize the summary; the fallback keeps CLI/API consumers working."""
    if score >= 90:
        return "excellent", "Excellent security posture"
    if score >= 75:
        return "good", "Good security posture with minor gaps"
    if score >= 50:
        return "moderate", "Moderate security posture â€” several improvements needed"
    return "poor", "Poor security posture â€” immediate action required"
