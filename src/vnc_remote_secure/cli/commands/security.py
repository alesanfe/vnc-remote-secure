"""Security umbrella commands — aggregated posture/audit reports."""


def _security_check(args) -> int:
    """Aggregate every security audit into one report.

    Combines the posture score, config validation findings, the
    listener audit (public binds on internal ports), and doctor's
    security checks — a single ``vnc-remote security check`` is the
    answer to "is this deployment safe right now", not three separate
    commands the operator has to remember.
    """
    from vnc_remote_secure.core.config import get_config, load_env_file

    load_env_file()
    config = get_config()

    critical = 0
    warnings = 0

    for section in (
        _posture_section,
        _config_findings_section,
        lambda: _listener_audit_section(config),
        _doctor_security_section,
    ):
        c, w = section()
        critical += c
        warnings += w

    print(f"\nResult: {critical} critical, {warnings} warnings")
    if critical:
        print(
            "Security check FAILED — resolve critical findings " "before exposing this deployment."
        )
        return 1
    print("Security check passed.")
    return 0


def _posture_section() -> tuple[int, int]:
    """Posture score — returns (critical, warnings)."""
    try:
        from vnc_remote_secure.security.posture import calculate_posture

        report = calculate_posture()
        score = report.get("score", 0)
        blocking = report.get("blocking_findings", [])
        print(f"Posture score: {score}/100 " f"({report.get('summary', '')})")
        critical = len(blocking)
        for f in blocking:
            print(f"  [CRITICAL] {f.get('message', f)}")
        warnings = sum(1 for c in report.get("checks", []) if c.get("status") == "warn")
        return critical, warnings
    except Exception as exc:  # noqa: BLE001
        print(f"Posture check unavailable: {exc}")
        return 0, 0


def _config_findings_section() -> tuple[int, int]:
    """Config validation findings — returns (critical, warnings)."""
    try:
        from vnc_remote_secure.core.config_inspector import validate_config

        critical = warnings = 0
        for f in validate_config():
            sev = f.get("severity", "warning")
            tag = "CRITICAL" if sev == "critical" else "WARNING"
            print(f"  [{tag}] config: {f.get('message', f)}")
            if sev == "critical":
                critical += 1
            else:
                warnings += 1
        return critical, warnings
    except Exception as exc:  # noqa: BLE001
        print(f"Config validation unavailable: {exc}")
        return 0, 0


def _listener_audit_section(config) -> tuple[int, int]:
    """Listener audit (public binds on internal ports)."""
    try:
        from vnc_remote_secure.core.service_manager import audit_internal_listeners

        findings = audit_internal_listeners(config)
        for f in findings:
            print(f"  [CRITICAL] listener: {f}")
        return len(findings), 0
    except Exception as exc:  # noqa: BLE001
        print(f"Listener audit unavailable: {exc}")
        return 0, 0


def _doctor_security_section() -> tuple[int, int]:
    """Doctor checks whose name starts with ``security.``."""
    try:
        from vnc_remote_secure.core.doctor import run_doctor

        critical = warnings = 0
        result = run_doctor(as_json=True)
        for c in result.get("checks", []):
            name = c.get("name", "")
            if not name.startswith("security."):
                continue
            status = c.get("status")
            if status == "fail":
                print(f"  [CRITICAL] {name}: {c.get('message', '')}")
                critical += 1
            elif status == "warn":
                print(f"  [WARNING] {name}: {c.get('message', '')}")
                warnings += 1
        return critical, warnings
    except Exception as exc:  # noqa: BLE001
        print(f"Doctor checks unavailable: {exc}")
        return 0, 0


def cmd_security(args):
    """Security umbrella (check)."""
    actions = {"check": _security_check}
    handler = actions.get(getattr(args, "security_action", ""))
    if handler is None:
        print(f"Unknown security action: " f"{getattr(args, 'security_action', '')}")
        return 1
    return handler(args)
