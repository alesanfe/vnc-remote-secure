"""Self-upgrade with automatic rollback.

An upgrade is only as safe as its rollback path. The flow:

1. ``upgrade_check`` reports the installed version and (when a
   distribution channel is reachable) the newest available one.
2. ``perform_upgrade`` takes a full backup *before* touching the
   package, records ``upgrade_state.json`` (previous version +
   backup path — the rollback receipt), installs the new package,
   then verifies the fresh install in a NEW process.
3. A failed verification triggers ``perform_rollback``: restore the
   backup and reinstall the recorded previous version.

Distribution channels: the package name on PyPI by default, or an
explicit source via ``--from`` (local wheel/sdist, VCS URL, or a
requirements-style specifier). A project published nowhere simply
gets "no newer version found" from ``--check`` — honest, not an
error.
"""
import json
import logging
import os
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

_PACKAGE = 'vnc-remote-secure'
_PIP_TIMEOUT_S = 300
_CHECK_TIMEOUT_S = 8


def _state_path() -> str:
    """Return the rollback-receipt path."""
    from vnc_remote_secure.core.paths import get_run_dir
    return os.path.join(get_run_dir(), 'upgrade_state.json')


def _read_state() -> dict | None:
    """Read the recorded upgrade state (rollback receipt)."""
    try:
        with open(_state_path(), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_state(state: dict) -> None:
    """Persist the rollback receipt (best-effort — still proceed)."""
    try:
        path = _state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    except OSError:
        logger.warning(
            "Could not record upgrade state — automatic rollback "
            "will not be available for this upgrade")


def installed_version() -> str:
    """Return the running package version."""
    try:
        from vnc_remote_secure import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return 'unknown'


def _fetch_available_version() -> str | None:
    """Query PyPI for the newest published version (short timeout)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            f'https://pypi.org/pypi/{_PACKAGE}/json',
            headers={'Accept': 'application/json',
                     'User-Agent': f'{_PACKAGE}-upgrade-check'})
        with urllib.request.urlopen(req, timeout=_CHECK_TIMEOUT_S) as r:
            data = json.loads(r.read().decode('utf-8'))
        return data.get('info', {}).get('version')
    except Exception:  # noqa: BLE001 - offline/not published/any net issue
        return None


def upgrade_check() -> dict:
    """Report installed vs available versions.

    Returns ``{'current', 'available', 'update', 'source'}`` —
    ``available``/``update`` are None when no channel is reachable
    or the package is not published.
    """
    current = installed_version()
    available = _fetch_available_version()
    return {
        'current': current,
        'available': available,
        'update': (available if available and available != current
                   else None),
        'source': f'pypi:{_PACKAGE}',
    }


def _version_key(ver: str):
    """Best-effort version ordering tuple for downgrade detection."""
    try:
        from packaging.version import Version
        return (0, Version(ver))
    except Exception:  # noqa: BLE001 - packaging missing/unparseable
        # Fallback: numeric tuple, zero-padded — good enough for
        # semver-ish strings, never worse than refusing to compare.
        try:
            return (1, tuple(int(p) for p in ver.split('.')))
        except (ValueError, AttributeError):
            return (2, ver)


def _is_index_spec(spec: str) -> bool:
    """True when ``spec`` resolves against the package index.

    Local paths, URLs and VCS strings are exempt from index-only flags
    like ``--only-binary :all:``.
    """
    return not (os.path.sep in spec or '://' in spec
                or spec.endswith(('.whl', '.tar.gz', '.zip'))
                or spec.startswith(('.', '/', 'git+')))


def _pip_install(spec: str) -> tuple[bool, str]:
    """Run ``pip install`` for ``spec``; returns (ok, tail_of_output).

    ``--isolated`` ignores ``PIP_*`` environment variables and pip
    config files — a tampered ``PIP_INDEX_URL``/``PIP_TRUSTED_HOST``
    cannot redirect the upgrade to a hostile index or disable TLS
    verification. Proxy variables still apply (they are read by the
    HTTP stack, not by pip config).
    """
    cmd = [sys.executable, '-m', 'pip', '--isolated', 'install',
           '--upgrade', '--disable-pip-version-check']
    if _is_index_spec(spec):
        # Index installs take wheels only — a sdist install would run
        # arbitrary build-time code (setup.py) on this host.
        cmd.append('--only-binary')
        cmd.append(':all:')
    cmd.append(spec)
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_PIP_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f'pip failed to run: {e}'
    out = (res.stdout or '') + (res.stderr or '')
    if res.returncode != 0:
        # Tail only: a full pip traceback drowns the actionable line.
        return False, '\n'.join(out.strip().splitlines()[-15:])
    return True, out


def _verify_new_install(_expected_prev: str) -> tuple[bool, str]:
    """Verify the freshly installed package in a NEW process.

    The current interpreter still holds the OLD modules — checking
    here would report the old version forever. A subprocess sees the
    new install. ``_expected_prev`` is kept for call-site clarity —
    the installed version is compared by the caller, not here.
    """
    try:
        res = subprocess.run(
            [sys.executable, '-c',
             'import vnc_remote_secure; print(vnc_remote_secure.__version__)'],
            capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f'new install not importable: {e}'
    ver = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ''
    if res.returncode != 0 or not ver:
        return False, 'new install failed to import'
    return True, ver


def perform_upgrade(source: str | None = None) -> dict:
    """Upgrade the package with automatic rollback on failure.

    Args:
        source: pip-installable spec (wheel path, VCS URL, version
            pin like ``vnc-remote-secure==1.2.3``). ``None`` means
            the package name on the default index.

    Returns:
        ``{'ok', 'previous', 'version'|'error', 'backup', 'rolled_back'}``.
    """
    from vnc_remote_secure.core.backup import create_backup

    previous = installed_version()
    spec = source or _PACKAGE
    result = {'ok': False, 'previous': previous, 'rolled_back': False,
              'backup': None}

    # Anti-downgrade guard BEFORE the backup: a pinned ``==`` spec
    # naming an OLDER version than the installed one is a downgrade
    # attempt — the upgrade path must not silently install it
    # (rollback downgrades through perform_rollback, which does not
    # pass through here). Checked before spending I/O on a backup for
    # an operation that will be refused.
    if '==' in spec:
        pinned = spec.rsplit('==', 1)[1].strip()
        if (previous != 'unknown'
                and _version_key(pinned) < _version_key(previous)):
            result['error'] = (
                f'refusing downgrade: requested {pinned} < installed '
                f'{previous} (use "vnc-remote rollback" for a controlled '
                'revert)')
            return result

    # 1. Backup BEFORE touching anything — the rollback receipt only
    #    matters if the pre-upgrade state is captured first.
    try:
        result['backup'] = create_backup()
    except Exception as e:  # noqa: BLE001
        result['error'] = f'pre-upgrade backup failed: {e} — aborting'
        return result

    _write_state({
        'previous_version': previous,
        'backup': result['backup'],
        'source': spec,
        'started': time.time(),
    })

    # 2. Install the new package.
    ok, out = _pip_install(spec)
    if not ok:
        logger.warning("Upgrade pip install failed:\n%s", out)
        result['error'] = 'pip install failed (see log)'
        result['rolled_back'] = perform_rollback()['ok']
        return result

    # 3. Verify the new install in a fresh interpreter.
    ok, ver = _verify_new_install(previous)
    if not ok:
        result['error'] = f'post-upgrade verification failed: {ver}'
        result['rolled_back'] = perform_rollback()['ok']
        return result

    # Post-install downgrade check covers sources whose version cannot
    # be known upfront (local wheel, VCS ref): if the resolved version
    # is older than what we started with, revert automatically.
    if (previous != 'unknown'
            and _version_key(ver) < _version_key(previous)):
        logger.warning(
            "Installed version %s is older than %s — rolling back",
            ver, previous)
        result['error'] = (
            f'install resolved to older version {ver} — reverted')
        result['rolled_back'] = perform_rollback()['ok']
        return result

    _write_state({
        'previous_version': previous,
        'version': ver,
        'backup': result['backup'],
        'source': spec,
        'finished': time.time(),
    })
    result.update(ok=True, version=ver)
    return result


def perform_rollback() -> dict:
    """Restore the recorded pre-upgrade state.

    Restores config/secrets/state from the recorded backup, then
    reinstalls the previous package version when the receipt knows
    it. Returns ``{'ok', 'restored', 'error'}``.
    """
    from vnc_remote_secure.core.backup import restore_backup

    state = _read_state()
    if not state:
        return {'ok': False, 'error': 'no upgrade state recorded '
                '(nothing to roll back)'}
    backup_path = state.get('backup')
    if not backup_path or not os.path.isfile(backup_path):
        return {'ok': False, 'error': 'recorded backup missing — '
                'manual restore required (vnc-remote restore <file>)'}

    result: dict = {'ok': False}
    try:
        restore_backup(backup_path)
        result['restored'] = backup_path
    except Exception as e:  # noqa: BLE001
        result['error'] = f'backup restore failed: {e}'
        return result

    prev = state.get('previous_version')
    if prev and prev != 'unknown':
        ok, out = _pip_install(f'{_PACKAGE}=={prev}')
        if not ok:
            logger.warning("Rollback pip reinstall failed:\n%s", out)
            result['error'] = ('state restored but package reinstall '
                               'failed — reinstall manually')
            return result
    result['ok'] = True
    return result
