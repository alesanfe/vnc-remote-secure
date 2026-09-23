"""Lifecycle commands: install, start, stop, restart, status, service.

uninstall.
"""
import json
import os
import sys
from contextlib import suppress

from vnc_remote_secure.cli._common import (
    _audit_cli,
    _find_project_root,
    _is_windows,
)


def _apply_no_ssl(args) -> bool:
    """Apply ``--no-ssl`` to the environment before ``startup()``.

    Must run BEFORE ``startup()``/``apply_profile``: the hardened-profile
    lock re-asserts ``TLS_ENABLED=true``, so writing the env vars
    afterwards would silently defeat the lock.

    Returns ``False`` (with an error printed) when the flag conflicts
    with a profile that mandates TLS.
    """
    if not getattr(args, 'no_ssl', False):
        return True
    from vnc_remote_secure.security.profiles import (
        _PROFILE_ALIASES,
        get_profile,
    )
    # Resolve legacy aliases (home-lan → trusted-lan, ...) — get_profile()
    # returns the raw env value, so an aliased hardened profile would
    # otherwise slip past this check and --no-ssl would be silently
    # defeated by the profile lock further down.
    profile = _PROFILE_ALIASES.get(get_profile(), get_profile())
    if profile in ('public-hardened', 'private-overlay', 'trusted-lan'):
        print("Error: --no-ssl is incompatible with security profile "
              f"'{profile}' (TLS is mandatory).", file=sys.stderr)
        return False
    os.environ['TLS_ENABLED'] = 'false'
    os.environ['DISABLE_SSL'] = 'true'
    return True


def _print_install_summary(project_root):
    """Print the post-install summary (URL, profile, paths, next steps).

    An install that ends silently leaves the operator guessing where
    the entry point is — surface the effective URL, active profile,
    cert state and the immediate follow-up commands.
    """
    try:
        from vnc_remote_secure.core.config import get_config
        config = get_config()
    except Exception:  # noqa: BLE001
        return
    tls = bool(config.get('tls_enabled'))
    domain = (os.environ.get('DUCK_DOMAIN', '').strip()
              or '127.0.0.1')
    if config.get('nginx_enabled'):
        port = int(os.environ.get(
            'NGINX_HTTPS_PORT' if tls else 'NGINX_HTTP_PORT',
            '443' if tls else '80'))
    else:
        port = int(config.get('landing_port') or 8080)
    scheme = 'https' if tls else 'http'
    default_port = 443 if tls else 80
    url = (f'{scheme}://{domain}'
           + ('' if port == default_port else f':{port}'))
    print("\n=== Post-install summary ===")
    print(f"  URL:        {url}")
    print(f"  Profile:    {config.get('security_profile') or 'default'}")
    print(f"  TLS:        {'enabled' if tls else 'DISABLED'}")
    try:
        from vnc_remote_secure.security.tls_validation import (
            cert_days_remaining)
        days = cert_days_remaining()
        if days is not None:
            warn = ' — EXPIRES SOON' if days < 30 else ''
            print(f"  Cert:       {days} days remaining{warn}")
    except Exception:  # noqa: BLE001
        pass
    try:
        from vnc_remote_secure.core.paths import (
            get_config_dir, get_data_dir)
        print(f"  Config:     {get_config_dir()}")
        print(f"  Data:       {get_data_dir()}")
    except Exception:  # noqa: BLE001
        print(f"  Config:     {os.path.join(project_root, '.env')}")
    try:
        from vnc_remote_secure.core.config_inspector import (
            validate_config)
        findings = validate_config()
        crit = sum(1 for f in findings
                   if f.get('severity') == 'critical')
        warn = len(findings) - crit
        if crit or warn:
            print(f"  Warnings:   {crit} critical, {warn} warnings "
                  "(vnc-remote config validate)")
    except Exception:  # noqa: BLE001
        pass
    print("\n  Next steps:")
    print("    vnc-remote doctor          # verify the deployment")
    print("    vnc-remote start           # start all services")
    print("    vnc-remote session create  # share a timed link")


def cmd_install(args):
    """Install and configure the system via the platform adapter.

    The Python platform installer (``platform/{linux,windows}/installer.py``)
    is the canonical installation path. It creates directories, copies
    configuration, registers services, configures the firewall, and
    generates SSL certificates — no Bash or PowerShell delegation.
    """
    if args.dry_run:
        print("[DRY RUN] Would perform installation:")
        print("  1. Check prerequisites")
        print("  2. Install dependencies")
        print("  3. Configure VNC server")
        print("  4. Generate SSL certificates")
        print("  5. Configure firewall")
        print("  6. Start all services")
        return 0

    project_root = _find_project_root()
    # Apply the security profile before the installer reads config —
    # profile defaults (NGINX_ENABLED, TLS_ENABLED, PUBLIC_BIND_HOST)
    # must be visible or a hardened-profile install would skip the
    # nginx/firewall setup that `start` (which applies the profile in
    # startup()) will then require.
    from vnc_remote_secure.core.config import load_env_file
    from vnc_remote_secure.security.profiles import apply_profile
    load_env_file()
    apply_profile()
    try:
        if _is_windows():
            from vnc_remote_secure.platform.windows.installer import install
        else:
            from vnc_remote_secure.platform.linux.installer import install
        install(project_root=project_root)
        print("Installation completed successfully.")
        _print_install_summary(project_root)
        return 0
    except PermissionError as e:
        print(f"Error: {e}", file=sys.stderr)
        if not _is_windows():
            print("Hint: Linux install requires root. Run with sudo.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Installation failed: {e}", file=sys.stderr)
        return 1


def cmd_start(args):
    """Start all services via the unified service manager.

    The Python service manager is the canonical orchestrator on every
    platform. It acquires a cross-process lock, applies the security
    profile, checks for blocking findings, and starts exactly the
    services enabled by configuration — tracking PIDs so ``stop`` can
    kill the exact processes (no ``pkill -f``).
    """
    if args.dry_run:
        print("[DRY RUN] Would start all services via the service manager")
        return 0

    from vnc_remote_secure.core.lifecycle import startup
    from vnc_remote_secure.core.service_manager import start_all
    from vnc_remote_secure.security.profiles import get_blocking_findings

    if not _apply_no_ssl(args):
        return 1

    # Apply profile and load config before starting anything.
    startup()

    # In hardened profiles, refuse to start if blocking findings exist.
    blockers = get_blocking_findings()
    if blockers:
        print("Refusing to start: blocking security findings detected:", file=sys.stderr)
        for b in blockers:
            print(f"  [{b.get('code', 'BLOCK')}] {b.get('message', '')}", file=sys.stderr)
        return 1

    results = start_all()
    started = [name for name, pid in results.items() if pid]
    failed = [name for name, pid in results.items() if not pid]
    if started:
        print(f"Started: {', '.join(started)}")
    if failed:
        print(f"Failed to start: {', '.join(failed)}", file=sys.stderr)

    # When running as a Windows Service (or any foreground supervisor),
    # block until interrupted so the service manager stays alive.
    if getattr(args, 'foreground', False):
        import time
        print("Running in foreground mode; press Ctrl+C to stop.")
        # Watchdog loop: periodic liveness checks + auto-restart/alert.
        from vnc_remote_secure.core.config import get_config as _get_cfg
        from vnc_remote_secure.core.service_manager import watchdog_tick
        config = _get_cfg()
        interval = int(config.get('healthcheck_interval', 30) or 30)
        last_check = time.monotonic()
        import signal as _sig

        def _term(_signum, _frame):
            # SIGTERM (systemd stop / docker stop / SCM) — the default
            # handler kills the supervisor mid-loop, orphaning the
            # children it owns. Translate to KeyboardInterrupt so the
            # same cleanup path runs.
            raise KeyboardInterrupt
        for _name in ('SIGTERM', 'SIGINT'):
            with suppress(AttributeError, ValueError, OSError):
                # e.g. no SIGTERM on Windows console main thread
                _sig.signal(getattr(_sig, _name), _term)
        try:
            while True:
                time.sleep(1)
                if time.monotonic() - last_check >= interval:
                    last_check = time.monotonic()
                    watchdog_tick(config)
        except KeyboardInterrupt:
            pass
        # The foreground supervisor owns its children — exiting the
        # watchdog must stop them or they stay orphaned after Ctrl+C
        # (the PID files would point at dead parents and `stop` would
        # still clean up, but the operator asked to stop). systemd and
        # the Windows SCM run their own ExecStop/`stop` on top; a
        # second stop_all is idempotent.
        try:
            from vnc_remote_secure.core.service_manager import stop_all
            print("Stopping services...")
            stop_all()
        except Exception as e:  # noqa: BLE001 - shutdown best-effort
            print(f"Warning: could not stop all services: {e}",
                  file=sys.stderr)
        return 0

    return 0 if not failed else 1


def cmd_stop(args):
    """Stop all services via the unified service manager (by PID)."""
    if args.dry_run:
        print("[DRY RUN] Would stop all services via the service manager")
        return 0

    from vnc_remote_secure.core.service_manager import stop_all
    results = stop_all(force=getattr(args, 'force', False))
    if 'error' in results:
        print(f"Error: {results['error']}", file=sys.stderr)
        return 1
    stopped = [name for name, ok in results.items() if ok]
    not_stopped = [name for name, ok in results.items() if not ok]
    if stopped:
        print(f"Stopped: {', '.join(stopped)}")
    if not_stopped:
        print(f"Could not stop: {', '.join(not_stopped)}", file=sys.stderr)
    return 0 if not not_stopped else 1


def cmd_restart(args):
    """Restart all services via the unified service manager."""
    if args.dry_run:
        print("[DRY RUN] Would restart all services via the service manager")
        return 0

    # Re-apply the security profile and blockers — ``restart`` runs in
    # a fresh process that has not called startup(), so a hardened
    # profile's locked vars (TLS_ENABLED, DISABLE_SSL, MFA_REQUIRED)
    # and blocking findings would otherwise be skipped.
    from vnc_remote_secure.core.lifecycle import startup
    from vnc_remote_secure.core.service_manager import restart_all
    from vnc_remote_secure.security.profiles import get_blocking_findings
    if not _apply_no_ssl(args):
        return 1
    startup()
    blockers = get_blocking_findings()
    if blockers:
        print("Refusing to restart: blocking security findings detected:",
              file=sys.stderr)
        for b in blockers:
            print(f"  [{b.get('code', 'BLOCK')}] {b.get('message', '')}",
                  file=sys.stderr)
        return 1

    results = restart_all()
    started = [name for name, pid in results.items() if pid]
    failed = [name for name, pid in results.items() if not pid]
    if started:
        print(f"Restarted: {', '.join(started)}")
    if failed:
        print(f"Failed to restart: {', '.join(failed)}", file=sys.stderr)
    return 0 if not failed else 1


def cmd_status(args):
    """Check system status from real PIDs and health checks."""
    from vnc_remote_secure.core.service_manager import status_all
    results = status_all()
    # Augment with port-listening health from the monitoring module.
    try:
        from vnc_remote_secure.monitoring.health import get_service_health
        port_health = get_service_health()
    except (ImportError, RuntimeError):
        port_health = {}
    if args.json:
        print(json.dumps({'services': results, 'port_health': port_health}, indent=2))
    else:
        print(f"{'Service':<12} {'PID':<8} {'Running':<8} {'Port'}")
        print(f"{'-' * 12} {'-' * 8} {'-' * 8} {'-' * 4}")
        for name, info in results.items():
            pid = info.get('pid') or '-'
            if info.get('enabled') is False:
                running = 'disabled'
                port = '-'
            else:
                running = 'yes' if info.get('running') else 'no'
                port = 'up' if port_health.get(name) else 'down'
            print(f"{name:<12} {pid!s:<8} {running:<8} {port}")
    running_count = sum(1 for s in results.values() if s.get('running'))
    return 0 if running_count else 1


def cmd_service(args):
    """Run in service mode (foreground, for systemd/Windows Services)."""
    _find_project_root()
    if args.dry_run:
        print("[DRY RUN] Would run in service mode (foreground)")
        return 0

    if not getattr(args, 'run', False):
        print("Error: --run flag required for service mode", file=sys.stderr)
        return 1

    # `service --run` is an alias for `start --foreground`: delegate so
    # the watchdog loop exists in exactly one place (cmd_start).
    print("[SERVICE] Starting VNC Remote Secure in service mode...")
    args.foreground = True
    rc = cmd_start(args)
    if rc != 0:
        print(f"[SERVICE] Failed to start services (exit code {rc})", file=sys.stderr)
    return rc


def cmd_uninstall(args):
    """Remove all project changes via the canonical Python uninstaller."""
    if args.dry_run:
        print("[DRY RUN] Would uninstall (stop services, remove firewall rules, configs)")
        return 0

    from vnc_remote_secure.core.uninstall import uninstall
    keep_data = getattr(args, 'keep_data', False)
    results = uninstall(keep_data=keep_data, force=True)
    ok_steps = [k for k, v in results.items() if v]
    fail_steps = [k for k, v in results.items() if not v]
    if ok_steps:
        print(f"Completed: {', '.join(ok_steps)}")
    if fail_steps:
        print(f"Failed: {', '.join(fail_steps)}", file=sys.stderr)
    _audit_cli('uninstall',
               'failure' if fail_steps else 'success',
               f'keep_data={keep_data}')
    return 0 if not fail_steps else 1
