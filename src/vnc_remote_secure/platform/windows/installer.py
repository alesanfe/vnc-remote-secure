"""Windows installer for VNC Remote Secure.

Creates the ProgramData directory structure, configures Windows
Firewall rules for the service ports, generates self-signed SSL
certificates when none are present, and provisions UltraVNC if it
is not already installed.
"""
import contextlib
import logging
import os
import shutil
import subprocess
import tempfile

import httpx
import tenacity

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.constants import (
    DEFAULT_LANDING_PORT,
)
from vnc_remote_secure.core.paths import (
    ensure_dirs,
    get_config_dir,
    get_data_dir,
    get_log_dir,
    get_ssl_dir,
)
from vnc_remote_secure.platform.windows.firewall import configure_firewall
from vnc_remote_secure.security.certificates import generate_self_signed

logger = logging.getLogger(__name__)

# Default UltraVNC download URL (portable x64 zip).
# Can be overridden via the ULTRAVNC_URL environment variable.
_DEFAULT_ULTRAVNC_URL = (
    'https://github.com/ultravnc/ultravnc/releases/download/1.4.3.6/'
    'UltraVNC_1_4_3_6_x64.zip'
)
_ULTRAVNC_INSTALL_DIR = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'UltraVNC')


def _is_elevated():
    """Return True when running with Administrator rights."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - assume elevated (tests/mocks)
        return True


def _find_ultravnc():
    """Locate winvnc.exe in PATH, ULTRAVNC_PATH, the default install.

    dir, or the project ``bin/ultravnc`` download directory (populated
    by ``tools/download_dependencies.py``).
    """
    # 1. Explicit path from environment.
    env_path = os.environ.get('ULTRAVNC_PATH', '')
    if env_path and os.path.isfile(env_path):
        return env_path
    # 2. Default install directory.
    candidate = os.path.join(_ULTRAVNC_INSTALL_DIR, 'winvnc.exe')
    if os.path.isfile(candidate):
        return candidate
    # 3. PATH lookup.
    found = shutil.which('winvnc.exe') or shutil.which('winvnc')
    if found:
        return found
    # 4. Project download directory (bin/ultravnc/<arch>/winvnc.exe).
    try:
        from vnc_remote_secure.core.paths import find_project_root
        root = find_project_root()
    except Exception:  # noqa: BLE001 - fall back to CWD search
        root = os.getcwd()
    arch = 'x64' if os.environ.get('PROCESSOR_ARCHITECTURE',
                                   'AMD64').upper() != 'X86' else 'x86'
    for sub in (arch, 'x64', 'x86', ''):
        candidate = os.path.join(
            root, 'bin', 'ultravnc', sub, 'winvnc.exe')
        if os.path.isfile(candidate):
            return candidate
    return None


def _verify_winvnc_hash(winvnc_path):
    """Verify ``winvnc.exe`` SHA-256 against the UltraVNC manifest.

    Reads ``third_party/manifests/ultravnc.json`` (canonical hash of
    the extracted binary — the same file ``verify_dependencies.py``
    checks). Returns ``True`` when the hash matches; returns ``True``
    also when the manifest/hash is unavailable so a packaging gap does
    not break installs, but logs a warning.
    """
    import hashlib
    import json

    candidates = []
    try:
        import vnc_remote_secure
        candidates.append(os.path.join(
            os.path.dirname(vnc_remote_secure.__file__),
            'third_party', 'manifests', 'ultravnc.json'))
    except Exception:  # noqa: BLE001
        pass
    try:
        from vnc_remote_secure.core.paths import find_project_root
        candidates.append(os.path.join(
            find_project_root(), 'src', 'vnc_remote_secure',
            'third_party', 'manifests', 'ultravnc.json'))
    except Exception:  # noqa: BLE001
        pass

    expected = None
    for cand in candidates:
        if os.path.isfile(cand):
            try:
                with open(cand, encoding='utf-8') as f:
                    expected = json.load(f).get('sha256')
            except (OSError, ValueError):
                continue
            break
    if not expected or expected == 'TBD':
        # A missing pin means the downloaded binary is unverifiable —
        # silently installing it trusts the network path completely.
        # Fail closed unless the operator explicitly opts out.
        if os.environ.get('ULTRAVNC_ALLOW_UNVERIFIED', '') == '1':
            logger.warning(
                "No UltraVNC checksum in manifest — installing "
                "unverified binary (ULTRAVNC_ALLOW_UNVERIFIED=1)")
            return True
        logger.error(
            "Refusing to install UltraVNC: no sha256 pinned in "
            "manifest (sha256 is 'TBD'). Pin a checksum or set "
            "ULTRAVNC_ALLOW_UNVERIFIED=1 to accept the risk")
        return False
    try:
        with open(winvnc_path, 'rb') as f:
            actual = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return False
    if actual.lower() != expected.lower():
        logger.warning(
            "UltraVNC hash mismatch: expected %s, got %s",
            expected[:16], actual[:16])
        return False
    return True


@tenacity.retry(
    stop=tenacity.stop_after_attempt(2),
    wait=tenacity.wait_exponential(min=2, max=10),
    retry=tenacity.retry_if_exception_type(httpx.TransportError),
    reraise=True)
def _download(url: str, zip_path: str) -> None:
    """Stream the UltraVNC zip to ``zip_path`` (httpx + one retry).

    A non-2xx response is a terminal failure, not a retry — mirroring
    the security.http_client rule that status answers are never
    re-sent.
    """
    with httpx.stream(
            'GET', url, follow_redirects=True,
            timeout=httpx.Timeout(60.0, read=120.0)) as resp:
        resp.raise_for_status()
        with open(zip_path, 'wb') as out:
            for chunk in resp.iter_bytes(chunk_size=1 << 16):
                out.write(chunk)


def _ensure_ultravnc():
    r"""Ensure UltraVNC is available; download and install if missing.

    Downloads the portable zip from the official UltraVNC release,
    extracts it to ``%ProgramFiles%\\UltraVNC``, and sets
    ``ULTRAVNC_PATH`` so the adapter can locate ``winvnc.exe``.

    If the download fails, logs a warning with manual instructions.
    """
    if _find_ultravnc() is not None:
        logger.info("UltraVNC found: %s", _find_ultravnc())
        return

    url = os.environ.get('ULTRAVNC_URL', _DEFAULT_ULTRAVNC_URL)
    # Only HTTPS downloads — a file:// or http:// URL would silently
    # bypass the checksum-verified TLS path below.
    if not url.lower().startswith('https://'):
        logger.error("Refusing non-HTTPS UltraVNC URL: %s", url)
        return
    logger.info("UltraVNC not found; downloading from %s ...", url)

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = os.path.join(tmp_dir, 'ultravnc.zip')
            # httpx streaming download: explicit timeouts (a stalled
            # mirror can't hang install forever) and one retry on
            # transport failures. Redirects are followed (GitHub
            # release → CDN); integrity is enforced by the manifest
            # SHA-256 check on winvnc.exe below, not by pinning.
            _download(url, zip_path)
            logger.info("Downloaded UltraVNC archive: %s", zip_path)

            os.makedirs(_ULTRAVNC_INSTALL_DIR, exist_ok=True)
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Reject member paths that escape the install dir
                # (zip-slip) — the archive is downloaded over TLS but
                # a compromised mirror/MITM must not write anywhere
                # else on disk. Same check as backup.py's tar filter.
                dest = os.path.realpath(_ULTRAVNC_INSTALL_DIR)
                for member in zf.namelist():
                    target = os.path.realpath(
                        os.path.join(dest, member))
                    if not target.startswith(dest + os.sep):
                        raise RuntimeError(
                            f"Unsafe path in UltraVNC archive: {member}")
                try:
                    zf.extractall(dest, filter='data')  # pylint: disable=unexpected-keyword-arg
                except TypeError:
                    zf.extractall(dest)
            logger.info("Extracted UltraVNC to %s", _ULTRAVNC_INSTALL_DIR)

        # The portable zip nests binaries under arch dirs (x64/, x86/)
        # — winvnc.exe is not at the archive root. Search recursively,
        # preferring the machine arch like _find_ultravnc() does.
        arch = 'x64' if os.environ.get(
            'PROCESSOR_ARCHITECTURE', 'AMD64').upper() != 'X86' else 'x86'
        winvnc = None
        for sub in (arch, 'x64', 'x86'):
            cand = os.path.join(_ULTRAVNC_INSTALL_DIR, sub, 'winvnc.exe')
            if os.path.isfile(cand):
                winvnc = cand
                break
        if winvnc is None:
            for dirpath, _dirs, files in os.walk(_ULTRAVNC_INSTALL_DIR):
                if 'winvnc.exe' in files:
                    winvnc = os.path.join(dirpath, 'winvnc.exe')
                    break
        if winvnc:
            # Verify the extracted binary against the manifest
            # checksum — the download is otherwise unauthenticated
            # (plain zip over TLS; a compromised mirror or MITM would
            # ship an arbitrary service binary).
            if _verify_winvnc_hash(winvnc):
                os.environ['ULTRAVNC_PATH'] = winvnc
                logger.info("UltraVNC provisioned: %s", winvnc)
            else:
                logger.warning(
                    "UltraVNC binary at %s failed SHA-256 verification "
                    "against third_party/manifests/ultravnc.json — "
                    "removing it. Install UltraVNC manually and set "
                    "ULTRAVNC_PATH.",
                    winvnc,
                )
                with contextlib.suppress(OSError):
                    os.remove(winvnc)
        else:
            logger.warning(
                "UltraVNC archive extracted but winvnc.exe not found at %s. "
                "The archive layout may have changed; install UltraVNC manually.",
                winvnc,
            )
    except (OSError, httpx.HTTPError) as exc:
        logger.warning(
            "Failed to download UltraVNC automatically: %s. "
            "Please install UltraVNC manually from https://uvnc.eu/downloads/ "
            "and set ULTRAVNC_PATH in your .env file.",
            exc,
        )


def _copy_package_to_programdata():
    r"""Copy the Python package into %ProgramData%\\VncRemoteSecure\\src.

    The ``service-run.py`` launcher registered as the service binary
    puts ``%ProgramData%\\VncRemoteSecure\\src`` on ``sys.path`` so the
    service can import ``vnc_remote_secure`` without requiring a pip
    install (sc.exe services cannot set environment variables).
    Stale package files are removed first so deletions propagate.
    """
    import sys
    pkg_src = os.path.join(
        os.path.dirname(sys.modules['vnc_remote_secure'].__file__))
    base = os.path.join(
        os.environ.get('ProgramData', r'C:\ProgramData'),
        'VncRemoteSecure', 'src')
    pkg_dst = os.path.join(base, 'vnc_remote_secure')
    try:
        os.makedirs(base, exist_ok=True)
        if os.path.isdir(pkg_dst):
            shutil.rmtree(pkg_dst)
        shutil.copytree(
            pkg_src, pkg_dst,
            ignore=shutil.ignore_patterns(
                '__pycache__', '*.pyc', '*.pyo', '.git'))
        logger.info("Package copied to %s", pkg_dst)
        # Launcher used as the Windows Service binary: it puts the copied
        # package on sys.path so the service works without a pip install.
        launcher = os.path.join(
            os.path.dirname(base), 'service-run.py')
        with open(launcher, 'w', encoding='utf-8') as f:
            f.write(
                'import os, sys\n'
                'sys.path.insert(0, os.path.join(os.path.dirname('
                'os.path.abspath(__file__)), "src"))\n'
                'from vnc_remote_secure.cli import main\n'
                'main()\n')
        logger.info("Service launcher written to %s", launcher)
        # Seed config.env from .env.example so the service and manual
        # CLI invocations read the same configuration (load_env_file
        # discovers %ProgramData%\VncRemoteSecure\config.env). An
        # existing config is never overwritten.
        cfg_dst = os.path.join(os.path.dirname(base), 'config.env')
        env_example = os.path.join(
            os.path.dirname(os.path.dirname(pkg_src)), '.env.example')
        if not os.path.isfile(cfg_dst) and os.path.isfile(env_example):
            shutil.copyfile(env_example, cfg_dst)
            # os.chmod is a no-op on Windows ACLs — the seeded config
            # will hold secrets, so restrict it like a private key.
            try:
                from vnc_remote_secure.security.certificates import _restrict_key_permissions
                _restrict_key_permissions(cfg_dst, writable=True)
            except Exception:  # noqa: BLE001
                with contextlib.suppress(OSError):
                    os.chmod(cfg_dst, 0o600)
            logger.info("Config seeded at %s (edit and set secrets)",
                        cfg_dst)
    except OSError as exc:
        logger.warning("Could not copy package to %s: %s", pkg_dst, exc)


def install(project_root=None, configure_firewall_rules=True):
    """Perform a full Windows installation.

    Args:
        project_root: Path to the project source tree (unused for file
            copy on Windows; ProgramData is the install target).
        configure_firewall_rules: Whether to open firewall ports.

    Returns:
        ``True`` if the installation completed successfully.
    """
    # Parity with the Linux installer's geteuid check: service
    # registration, firewall rules, ProgramData writes and the
    # restricted runtime user all require elevation — fail fast
    # rather than half-installing.
    if not _is_elevated():
        raise PermissionError(
            "Windows install requires an elevated (Administrator) shell")
    # 1. Create standard directories under ProgramData.
    ensure_dirs()

    # 2. Copy the package so the Windows service can import it via the
    #    service-run.py launcher registered by platform/windows/
    #    services.py (works without a pip install, mirroring the Linux
    #    /opt layout).
    _copy_package_to_programdata()

    # 3. Provision UltraVNC if not already installed.
    _ensure_ultravnc()

    # 4. Configure Windows Firewall. Only the public entry point gets a
    #    rule — on Windows that is the landing portal (nginx is not
    #    supported). Backend services stay on 127.0.0.1 and must NOT be
    #    opened here: a loopback-only service needs no rule, and opening
    #    them would expose every backend directly if an operator later
    #    sets a *_HOST=0.0.0.0, bypassing the Zero-Trust gateway model.
    #    This matches Firewall.ps1's "only the gateway port" behaviour.
    if configure_firewall_rules:
        public_bind = os.environ.get(
            'PUBLIC_BIND_HOST',
            os.environ.get('BIND_HOST', '127.0.0.1'))
        if public_bind not in ('127.0.0.1', 'localhost', '::1'):
            landing_port = int(
                os.environ.get('LANDING_PORT', str(DEFAULT_LANDING_PORT)))
            configure_firewall(landing_port, 'tcp')
        else:
            logger.info(
                "Loopback-only deployment — no firewall rules needed "
                "(PUBLIC_BIND_HOST=%s)", public_bind)

    # 5. Generate self-signed SSL certificate if none exists.
    cert_path = os.path.join(get_ssl_dir(), 'fullchain.pem')
    key_path = os.path.join(get_ssl_dir(), 'privkey.pem')
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        try:
            generate_self_signed(cert_path, key_path)
        except (OSError, ValueError) as exc:
            logger.warning("Self-signed certificate generation failed: %s", exc)

    # 6. Create the temporary remote access user if configured.
    _create_temp_user()

    # 7. Register the Windows Service so the application survives reboots.
    try:
        from vnc_remote_secure.platform.windows.services import (
            SERVICE_NAME,
            install_service,
        )
        install_service(SERVICE_NAME)
        logger.info("Registered Windows Service '%s'.", SERVICE_NAME)
    except Exception as exc:  # noqa: BLE001 - service registration is best-effort
        logger.warning("Could not register Windows Service: %s", exc)

    return True


def _create_temp_user():
    """Create the temporary remote access user if configured.

    On Windows, the temp user is created via ``net user`` and given a
    password if ``TEMP_USER_PASS`` is set. The user is removed on exit
    unless ``KEEP_TEMP_USER=true``.
    """
    temp_user = os.environ.get('TEMP_USER', 'remote')
    temp_pass = os.environ.get('TEMP_USER_PASS', '')
    keep_temp = env_flag('KEEP_TEMP_USER', 'false')

    if not temp_user:
        logger.info("TEMP_USER is empty; skipping temp user creation.")
        return

    if keep_temp:
        logger.info("KEEP_TEMP_USER=true; creating persistent temp user '%s'.", temp_user)
    else:
        logger.info("Creating temp user '%s' (will be removed on exit).", temp_user)

    try:
        # Use the restricted variant: the temp remote-access user must
        # not get interactive logon (Users group) — it exists only so
        # service/VNC processes can run under a non-admin context.
        from vnc_remote_secure.platform.windows.permissions import (
            create_restricted_user,
        )
        create_restricted_user(temp_user, temp_pass if temp_pass else None)
        logger.info("Created restricted temp user: %s", temp_user)
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.warning("Failed to create temp user '%s': %s", temp_user, exc)


def uninstall():
    """Remove installed directories, firewall rules, and the Windows Service.

    Note: The canonical uninstall flow is in ``core/uninstall.py`` which
    delegates to the platform adapter. This function is retained as a
    platform-specific helper for direct programmatic use.
    """
    # Remove the Windows Service first so it does not restart the app.
    try:
        from vnc_remote_secure.platform.windows.services import (
            SERVICE_NAME,
            remove_service,
        )
        remove_service(SERVICE_NAME)
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        logger.warning("Could not remove Windows Service: %s", exc)

    # Remove every rule under the prefix — covers rules created by the
    # installer, Firewall.ps1 and any operator-added rule (remove_
    # firewall_rule treats the name as a DisplayName prefix).
    from vnc_remote_secure.platform.windows.firewall import remove_firewall_rule
    remove_firewall_rule('VncRemoteSecure')
    for path in (get_config_dir(), get_data_dir(), get_log_dir(), get_ssl_dir()):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    return True
