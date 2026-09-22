"""Test fixtures for VNC Remote Secure.

Isolates runtime state (PID files, session stores, ephemeral sessions)
into a per-test-session temporary directory so tests do not pollute or
read from the real system runtime directory.
"""

import contextlib
import pytest

# Hypothesis deadlines flake under load (CI/loaded dev machines): a
# 200ms per-example budget is a timing assertion, not a correctness
# signal, and these tests exercise validators/parsers whose runtime
# varies with system contention. Disable the deadline globally; the
# per-test max_examples bounds still apply.
try:
    from hypothesis import HealthCheck, settings
    settings.register_profile(
        'vncrs', deadline=None,
        suppress_health_check=[HealthCheck.too_slow])
    settings.load_profile('vncrs')
except ImportError:
    pass


@pytest.fixture(autouse=True)
def _isolate_run_dir(monkeypatch, tmp_path):
    r"""Redirect get_run_dir() to a temporary directory for every test.

    This prevents tests from reading/writing the real /run/vnc-remote-secure
    (Linux) or C:\\ProgramData\\VncRemoteSecure\\run (Windows) directory,
    which would leak session state across test runs and across CLI
    invocations during development.
    """
    run_dir = tmp_path / 'run'
    log_dir = tmp_path / 'logs'
    data_dir = tmp_path / 'data'
    config_dir = tmp_path / 'config'
    ssl_dir = tmp_path / 'ssl'
    for d in (run_dir, log_dir, data_dir, config_dir, ssl_dir):
        d.mkdir(exist_ok=True)

    # Patch the path helpers at the source so all callers see the temp
    # paths (audit.jsonl, PID files, session stores, certs).
    from vnc_remote_secure.core import paths as paths_mod
    _overrides = {
        'get_run_dir': run_dir,
        'get_log_dir': log_dir,
        'get_data_dir': data_dir,
        'get_config_dir': config_dir,
        'get_ssl_dir': ssl_dir,
    }
    for fname, target in _overrides.items():
        monkeypatch.setattr(paths_mod, fname, lambda t=target: str(t))

    # Modules that bound the path helpers at TOP LEVEL via
    # ``from paths import get_run_dir`` hold a reference to the
    # original function — patching the module attribute alone leaves
    # them writing to the real run dir (a test run previously leaked
    # generated_credentials.env into the real %LOCALAPPDATA%).
    # Rebind the name inside each of those modules too.
    for mod_name in (
        'vnc_remote_secure.core.backup',
        'vnc_remote_secure.core.doctor',
        'vnc_remote_secure.core.service_manager',
        'vnc_remote_secure.core.uninstall',
        'vnc_remote_secure.platform.linux.installer',
        'vnc_remote_secure.platform.windows.installer',
        'vnc_remote_secure.security.authentication',
    ):
        try:
            mod = __import__(mod_name, fromlist=['x'])
        except Exception:
            continue
        for fname, target in _overrides.items():
            if getattr(mod, fname, None) is not None:
                monkeypatch.setattr(
                    mod, fname, lambda t=target: str(t))

    # Also reset the global ephemeral session store so each test starts
    # fresh (the store caches itself in a module-level singleton).
    import vnc_remote_secure.security.ephemeral_sessions as ephem_mod
    monkeypatch.setattr(ephem_mod, '_store', None)

    # Prevent ambient .env / config.env leakage: mark the default env
    # merge as already done so load_env_file() is a no-op during the
    # test. Tests that need a specific file can still call
    # load_env_file(path) explicitly (explicit paths always load).
    # Without this, the real .env on the developer machine changes
    # test outcomes (e.g. a LANDING_PASSWORD present locally turns
    # fallback-app tests into 401s).
    import vnc_remote_secure.core.config as config_mod
    monkeypatch.setattr(config_mod, '_ENV_LOADED', True)

    # Audit sinks are read from os.environ at call time — a developer
    # shell exporting AUDIT_LOG_FILE/AUDIT_MIRROR_FILE would write real
    # audit entries during tests. Scrub them unless a test sets them
    # explicitly (it can monkeypatch.setenv itself).
    monkeypatch.delenv('AUDIT_LOG_FILE', raising=False)
    monkeypatch.delenv('AUDIT_MIRROR_FILE', raising=False)


@pytest.fixture(autouse=True)
def _drain_ws_revocation_watchers():
    """Cancel revocation-watcher tasks orphaned by closed event loops.

    Services spawn ``watch_shared_revocation_async`` tasks with a 5 s
    poll interval; tests finish (and their ``asyncio.run`` loop dies)
    before the first tick, so the tasks are GC'd while pending — the
    ``Task was destroyed but it is pending`` noise. Cancelling them
    marks the future done even when the loop is already closed.
    """
    yield
    try:
        from vnc_remote_secure.security import websocket_registry as wr
        for task in list(wr._watcher_tasks):
            if not task.done():
                with contextlib.suppress(RuntimeError):
                    task.cancel()
        wr._watcher_tasks.clear()
        # Registered-but-never-closed fake connections leak across
        # tests via the process-global registry.
        reg = wr._registry
        if reg is not None:
            with reg._lock:
                reg._connections.clear()
                reg._by_session.clear()
    except Exception:  # noqa: BLE001 - teardown best-effort
        pass


_SHARED_STATE_TEST_NAMESPACES = (
    'rate_limit_lockouts', 'rate_limit_attempts', 'rate_limit_general',
    'websocket_revoked_sessions', 'ephemeral_revoked_sessions',
    'ephemeral_consumed', 'ephemeral_uses',
    'mfa_last_step', 'mfa_used_steps', 'mfa_used_recovery_codes',
    'step_up_auth_times',
)


@pytest.fixture(autouse=True)
def _clear_shared_state_namespaces():
    """Wipe shared-state test namespaces after every test.

    Lockouts, revocations, single-use claims and step-up times live in
    the sqlite backend, not the Python objects — a test that triggers
    one otherwise poisons every later test touching the same session
    id, client IP or username.
    """
    yield
    try:
        from vnc_remote_secure.security.shared_state import get_backend
        be = get_backend()
        for ns in _SHARED_STATE_TEST_NAMESPACES:
            for k in list(be.list_keys(ns)):
                be.delete(ns, k)
    except Exception:  # noqa: BLE001 - teardown best-effort
        pass
