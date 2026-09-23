"""Linux installer for VNC Remote Secure.

Copies project files into the standard system directories, installs
systemd unit files, creates runtime directories, configures the
service user, installs system packages, configures nginx and fail2ban,
and generates SSL certificates. Requires root privileges.
"""
import logging
import os
import shutil
import subprocess

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.core.constants import (
    DEFAULT_AUDIO_STREAM_PORT,
    DEFAULT_GAMEPAD_PORT,
    DEFAULT_HEALTH_PORT,
    DEFAULT_LANDING_PORT,
    DEFAULT_NGINX_HTTP_PORT,
    DEFAULT_NGINX_HTTPS_PORT,
    DEFAULT_NOVNC_PORT,
    DEFAULT_TTYD_PORT,
)
from vnc_remote_secure.core.paths import (
    ensure_dirs,
    get_config_dir,
    get_data_dir,
    get_log_dir,
    get_run_dir,
    get_ssl_dir,
)
from vnc_remote_secure.core.processes import run_cmd
from vnc_remote_secure.platform.linux.services import install_service
from vnc_remote_secure.platform.linux.users import create_runtime_user

logger = logging.getLogger(__name__)

# System packages required on Debian/Ubuntu.
_SYSTEM_PACKAGES = [
    'nginx',
    'fail2ban',
    'tigervnc-standalone-server',
    'tigervnc-common',
    'websockify',
    'openssl',
    'certbot',
    'python3-certbot-nginx',
    # Audio streaming feature (AUDIO_STREAM_ENABLED): ffmpeg does the
    # capture/encode; pulseaudio-utils provides pactl for default
    # source detection in the Linux adapter.
    'ffmpeg',
    'pulseaudio-utils',
    # Gamepad injection feature (GAMEPAD_ENABLED): evdev/uinput.
    'python3-evdev',
]

# Fail2ban jail configuration template.
_FAIL2BAN_JAIL = """\
[vnc-remote-novnc]
enabled = true
port = {novnc_port}
filter = vnc-remote
logpath = {log_dir}/novnc.log
maxretry = {max_retry}
findtime = {findtime}
bantime = {bantime}

[vnc-remote-terminal]
enabled = true
port = {ttyd_port}
filter = vnc-remote
logpath = {log_dir}/terminal.log
maxretry = {max_retry}
findtime = {findtime}
bantime = {bantime}

[vnc-remote-vnc]
enabled = true
port = {vnc_port}
filter = vnc-remote
logpath = {log_dir}/vnc.log
maxretry = {max_retry}
findtime = {findtime}
bantime = {bantime}
"""

# Fail2ban filter configuration.
_FAIL2BAN_FILTER = """\
[Definition]
# Web Terminal authentication failures (ttyd or Python terminal service)
failregex = ^.*(?:ttyd|terminal).*(?:failed|invalid|denied|unauthorized).*from <HOST>
            ^.*(?:ttyd|terminal).*<HOST>.*(?:failed|invalid|denied)
# noVNC/websockify connection errors
            ^.*websockify.*(?:error|reject).*<HOST>
            ^.*novnc.*(?:failed|denied).*<HOST>
# VNC server auth failures
            ^.*vnc.*(?:auth|fail|reject).*<HOST>
            ^.*tigervnc.*(?:auth|fail|reject).*<HOST>
# Generic auth failures (require "auth" context to avoid false positives)
            ^.*authentication failed.*from <HOST>
            ^.*invalid (?:password|credentials|login).*from <HOST>
            ^.*access denied.*from <HOST>
ignoreregex =
"""


def _run(cmd, check=True):
    """Run a command, logging output."""
    logger.info("Running: %s", ' '.join(cmd))
    result = run_cmd(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.warning("Command failed (%d): %s", result.returncode, result.stderr.strip())
        if check:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return result


def _install_system_packages():
    """Install required system packages via apt-get (Debian/Ubuntu)."""
    if not shutil.which('apt-get'):
        logger.warning("apt-get not found; skipping system package installation. "
                       "Install manually: %s", ', '.join(_SYSTEM_PACKAGES))
        return

    logger.info("Updating package lists...")
    _run(['apt-get', 'update', '-qq'], check=False)

    logger.info("Installing system packages: %s", ', '.join(_SYSTEM_PACKAGES))
    _run(['apt-get', 'install', '-y', '-qq'] + _SYSTEM_PACKAGES, check=False)


def _configure_nginx(project_root):
    """Copy and substitute the nginx reverse proxy configuration."""
    from vnc_remote_secure.core.config import get_config

    config = get_config()
    if not config.get('nginx_enabled', False):
        logger.info("Nginx disabled (NGINX_ENABLED=false); skipping nginx configuration.")
        return

    nginx_src = os.path.join(project_root, 'src', 'vnc_remote_secure', 'config', 'nginx.conf')
    if not os.path.isfile(nginx_src):
        # Package-relative fallback (pip-installed wheel).
        try:
            from importlib.resources import files

            nginx_src = str(files('vnc_remote_secure') / 'config' / 'nginx.conf')
        except Exception:  # noqa: BLE001
            pass
    if not os.path.isfile(nginx_src):
        logger.warning("nginx.conf template not found: %s", nginx_src)
        return

    # Read the template and substitute variables.
    with open(nginx_src, encoding='utf-8') as f:
        template = f.read()

    # Backend proxy protocols must match what the services actually
    # serve: they wrap their sockets with create_ssl_context() when a
    # cert pair resolves, so proxying plain HTTP to them would 502.
    # The env vars remain the escape hatch for exotic deployments.
    try:
        from vnc_remote_secure.security.certificates import create_ssl_context
        backend_proto = 'https' if create_ssl_context() else 'http'
    except Exception:  # noqa: BLE001
        backend_proto = 'http'

    # Backend hosts must match where the services actually bind — the
    # same <SERVICE>_HOST → BIND_HOST → loopback chain get_config()
    # uses. Substituting a bare env lookup would point nginx at
    # 127.0.0.1 while the backend listens on BIND_HOST → 502.
    def _host(*names, default='127.0.0.1'):
        for n in names:
            v = os.environ.get(n, '').strip()
            if v:
                return v
        return default

    _default_hsts = 'max-age=31536000; includeSubDomains'

    def _safe_header(value):
        """Return ``value`` safe to embed in a quoted nginx header.

        directive — CR/LF and raw double quotes are stripped (same
        contract as http_headers._safe_header_value).
        """
        cleaned = ''.join(
            ch for ch in str(value) if ch not in '\r\n"').strip()
        return cleaned or _default_hsts

    # Bare 'mysub' must become 'mysub.duckdns.org' — nginx server_name
    # would otherwise never match the real DuckDNS hostname (the same
    # normalization share links and ALLOWED_ORIGINS apply).
    from vnc_remote_secure.core.config import normalize_duck_domain
    substitutions = {
        'DUCK_DOMAIN': normalize_duck_domain(
            os.environ.get('DUCK_DOMAIN', '')) or 'localhost',
        'SSL_CERT': os.environ.get('SSL_CERT', os.path.join(get_ssl_dir(), 'fullchain.pem')),
        'SSL_KEY': os.environ.get('SSL_KEY', os.path.join(get_ssl_dir(), 'privkey.pem')),
        'NGINX_HTTP_PORT': str(config.get('nginx_http_port',
                                          DEFAULT_NGINX_HTTP_PORT)),
        'NGINX_HTTPS_PORT': str(config.get('nginx_https_port',
                                           DEFAULT_NGINX_HTTPS_PORT)),
        'NOVNC_HOST': _host('SERVE_NOVNC_HOST', 'NOVNC_HOST', 'BIND_HOST'),
        'NOVNC_PORT': str(config.get('novnc_port', DEFAULT_NOVNC_PORT)),
        'TTYD_HOST': _host('TTYD_HOST', 'BIND_HOST'),
        'TTYD_PORT': str(config.get('ttyd_port', DEFAULT_TTYD_PORT)),
        'HEALTH_WEB_HOST': _host('HEALTH_WEB_HOST', 'BIND_HOST'),
        'HEALTH_WEB_PORT': str(config.get('health_port', DEFAULT_HEALTH_PORT)),
        'HEALTH_BACKEND_PROTOCOL': os.environ.get('HEALTH_BACKEND_PROTOCOL', backend_proto),
        'AUDIO_BACKEND_PROTOCOL': os.environ.get('AUDIO_BACKEND_PROTOCOL', backend_proto),
        'GAMEPAD_BACKEND_PROTOCOL': os.environ.get('GAMEPAD_BACKEND_PROTOCOL', backend_proto),
        'NOVNC_BACKEND_PROTOCOL': os.environ.get('NOVNC_BACKEND_PROTOCOL', backend_proto),
        'TTYD_BACKEND_PROTOCOL': os.environ.get('TTYD_BACKEND_PROTOCOL', backend_proto),
        'LANDING_BACKEND_PROTOCOL': os.environ.get('LANDING_BACKEND_PROTOCOL', backend_proto),
        # Same default as security/http_headers.py — the operator's
        # HSTS_HEADER override must reach the edge too, not only the
        # backend-emitted headers. The value lands inside a quoted
        # nginx directive — CR/LF or a raw quote would inject
        # additional directives, so sanitise before substituting.
        'HSTS_HEADER': _safe_header(os.environ.get(
            'HSTS_HEADER', '')),
        'LANDING_HOST': _host('LANDING_HOST', 'BIND_HOST'),
        'LANDING_PORT': str(config.get('landing_port', DEFAULT_LANDING_PORT)),
        'AUDIO_STREAM_HOST': _host('AUDIO_STREAM_HOST', 'BIND_HOST'),
        'AUDIO_STREAM_PORT': str(config.get('audio_stream_port',
                                            DEFAULT_AUDIO_STREAM_PORT)),
        'GAMEPAD_HOST': _host('GAMEPAD_HOST', 'BIND_HOST'),
        'GAMEPAD_PORT': str(config.get('gamepad_port', DEFAULT_GAMEPAD_PORT)),
    }

    result = template
    for key, value in substitutions.items():
        # Every substituted value lands inside an nginx directive —
        # a CR/LF would inject extra directives into the generated
        # config (e.g. via a crafted DUCK_DOMAIN or *_HOST value).
        # Strip them defensively for every key, not just headers.
        safe_value = ''.join(ch for ch in str(value) if ch not in '\r\n')
        result = result.replace(f'${{{key}}}', safe_value)

    nginx_dst = '/etc/nginx/sites-available/vnc-remote-secure'
    nginx_link = '/etc/nginx/sites-enabled/vnc-remote-secure'
    os.makedirs(os.path.dirname(nginx_dst), exist_ok=True)
    with open(nginx_dst, 'w', encoding='utf-8') as f:
        f.write(result)
    logger.info("Installed nginx config: %s", nginx_dst)

    # Enable the site (symlink).
    if not os.path.exists(nginx_link):
        os.symlink(nginx_dst, nginx_link)
        logger.info("Enabled nginx site: %s", nginx_link)

    # Remove default site if present.
    default_link = '/etc/nginx/sites-enabled/default'
    if os.path.exists(default_link):
        os.remove(default_link)
        logger.info("Removed default nginx site.")

    # Test and reload nginx.
    _run(['nginx', '-t'], check=False)
    _run(['systemctl', 'reload', 'nginx'], check=False)


def _configure_fail2ban():
    """Create fail2ban jail and filter configurations for VNC services."""
    from vnc_remote_secure.core.config import get_config

    config = get_config()
    if not config.get('fail2ban_enabled', False):
        logger.info("Fail2ban disabled (FAIL2BAN_ENABLED=false); skipping configuration.")
        return

    if not shutil.which('fail2ban-server'):
        logger.warning("fail2ban not installed; skipping configuration.")
        return

    def _int(name, default):
        # These values are written verbatim into the fail2ban jail —
        # a non-numeric value (or one containing a newline) would
        # inject arbitrary ini directives.
        try:
            return int(os.environ.get(name, ''))
        except (TypeError, ValueError):
            return default

    max_retry = _int('FAIL2BAN_MAX_RETRY', 5)
    findtime = _int('FAIL2BAN_FINDTIME', 600)
    bantime = _int('FAIL2BAN_BANTIME', 3600)
    # LOG_DIR lands in the jail's logpath — strip CR/LF for the same
    # reason as the nginx template substitutions.
    log_dir = ''.join(
        ch for ch in get_log_dir() if ch not in '\r\n')

    jail_content = _FAIL2BAN_JAIL.format(
        novnc_port=config.get('novnc_port', 6080),
        ttyd_port=config.get('ttyd_port', 5000),
        vnc_port=config.get('vnc_port', 5901),
        log_dir=log_dir,
        max_retry=max_retry,
        findtime=findtime,
        bantime=bantime,
    )

    jail_dir = '/etc/fail2ban/jail.d'
    filter_dir = '/etc/fail2ban/filter.d'
    os.makedirs(jail_dir, exist_ok=True)
    os.makedirs(filter_dir, exist_ok=True)

    jail_path = os.path.join(jail_dir, 'vnc-remote.local')
    with open(jail_path, 'w', encoding='utf-8') as f:
        f.write(jail_content)
    logger.info("Installed fail2ban jail: %s", jail_path)

    filter_path = os.path.join(filter_dir, 'vnc-remote.conf')
    with open(filter_path, 'w', encoding='utf-8') as f:
        f.write(_FAIL2BAN_FILTER)
    logger.info("Installed fail2ban filter: %s", filter_path)

    _run(['systemctl', 'restart', 'fail2ban'], check=False)


def _configure_firewall():
    """Configure UFW firewall rules for VNC Remote Secure services.

    Opens only the ports required for external access (HTTPS, HTTP redirect,
    and optionally the landing page when nginx is disabled). Internal services
    bound to 127.0.0.1 are not exposed. If UFW is not installed, a warning is
    logged and the step is skipped.
    """
    from vnc_remote_secure.core.config import get_config

    config = get_config()
    nginx_enabled = config.get('nginx_enabled', False)
    https_port = config.get('nginx_https_port', DEFAULT_NGINX_HTTPS_PORT)
    http_port = config.get('nginx_http_port', DEFAULT_NGINX_HTTP_PORT)
    landing_port = config.get('landing_port', DEFAULT_LANDING_PORT)

    if not shutil.which('ufw'):
        logger.warning("ufw not installed; skipping firewall configuration. "
                       "Open ports manually if needed.")
        return

    logger.info("Configuring UFW firewall rules...")

    # Ensure UFW is enabled (non-interactive; allow existing SSH sessions).
    _run(['ufw', 'allow', 'OpenSSH'], check=False)
    _run(['ufw', '--force', 'enable'], check=False)

    # Tag rules with the 'vnc-remote' comment so the uninstaller's
    # remove_firewall_rule('vnc-remote') can find and delete them —
    # ufw delete needs the rule spec or number, not a bare name.
    if nginx_enabled:
        # nginx is the single point of entry: only expose 80/443.
        _run(['ufw', 'allow', f'{https_port}/tcp', 'comment', 'vnc-remote'],
             check=False)
        if http_port != https_port:
            _run(['ufw', 'allow', f'{http_port}/tcp', 'comment', 'vnc-remote'],
                 check=False)
        logger.info("UFW: opened ports %s (HTTPS) and %s (HTTP) for nginx.",
                    https_port, http_port)
    else:
        # Without nginx, expose the landing page port directly.
        _run(['ufw', 'allow', f'{landing_port}/tcp', 'comment', 'vnc-remote'],
             check=False)
        logger.info("UFW: opened port %s (landing) — nginx disabled.", landing_port)

    _run(['ufw', 'reload'], check=False)
    logger.info("UFW firewall configuration completed.")


def _generate_ssl_certificates():
    """Obtain SSL certificates.

    When ``DUCK_DOMAIN`` and ``EMAIL`` are configured, request a real
    Let's Encrypt certificate via certbot (parity with the historical
    ``make ssl-setup`` behaviour). Otherwise, generate a self-signed
    certificate.
    """
    from vnc_remote_secure.security.certificates import (
        generate_self_signed,
        request_letsencrypt,
    )

    cert_path = os.path.join(get_ssl_dir(), 'fullchain.pem')
    key_path = os.path.join(get_ssl_dir(), 'privkey.pem')

    if os.path.exists(cert_path) and os.path.exists(key_path):
        logger.info("SSL certificates already exist; skipping generation.")
        return

    # Let's Encrypt needs the FQDN — a bare 'mysub' would request a
    # cert for a non-existent hostname while nginx answers
    # 'mysub.duckdns.org'.
    from vnc_remote_secure.core.config import normalize_duck_domain
    domain = normalize_duck_domain(os.environ.get('DUCK_DOMAIN', ''))
    email = os.environ.get('EMAIL', '').strip()
    if domain and domain != 'localhost' and email:
        from vnc_remote_secure.core.validation import (
            ValidationError,
            validate_domain,
            validate_email,
        )
        try:
            validate_domain(domain, 'DUCK_DOMAIN')
            validate_email(email, 'EMAIL')
        except ValidationError as exc:
            logger.warning(
                "Invalid DUCK_DOMAIN/EMAIL for Let's Encrypt (%s); "
                "falling back to self-signed.", exc)
        else:
            if request_letsencrypt(domain, email, get_ssl_dir()):
                return
            logger.warning("Let's Encrypt request failed; falling back to self-signed.")

    logger.info("Generating self-signed SSL certificates...")
    try:
        generate_self_signed(cert_path, key_path)
        logger.info("SSL certificates generated: %s, %s", cert_path, key_path)
    except (OSError, ValueError) as exc:
        logger.warning("Failed to generate SSL certificates: %s", exc)


def _create_temp_user():
    """Create the temporary remote access user if configured.

    The account is created LOCKED: ``useradd -r -s /usr/sbin/nologin``
    (system account, no home, no interactive shell) — so neither
    password nor SSH-key login works out of the box. ``TEMP_USER_PASS``
    is applied so an operator can later enable the account (``usermod
    -s``) without re-creating it. Interactive access is opt-in, not
    the default.
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
        create_runtime_user(temp_user)
        logger.info("Created temp user: %s", temp_user)
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.warning("Failed to create temp user '%s': %s", temp_user, exc)
        return

    if temp_pass:
        try:
            from vnc_remote_secure.platform.linux.permissions import set_user_password
            set_user_password(temp_user, temp_pass)
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure (logs username, not the password)
            logger.info("Password set for temp user: %s", temp_user)
        except (OSError, subprocess.CalledProcessError) as exc:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure (logs username+error, not the password)
            logger.warning("Failed to set password for temp user '%s': %s", temp_user, exc)


def install(project_root=None, service_user='vnc-remote'):
    """Perform a full Linux installation.

    Args:
        project_root: Path to the project source tree. When ``None`` the
            detected project root is used.
        service_user: System user to create for service isolation.

    Returns:
        ``True`` if the installation completed successfully.
    """
    if os.geteuid() != 0:  # pylint: disable=no-member
        raise PermissionError("Linux install requires root privileges")
    if project_root is None:
        from vnc_remote_secure.core.paths import find_project_root
        project_root = find_project_root()

    logger.info("Starting Linux installation...")

    # 1. Install system packages (nginx, fail2ban, tigervnc, etc.).
    _install_system_packages()

    # 2. Create standard directories.
    ensure_dirs()

    # 3. Copy configuration files.
    config_src = os.path.join(project_root, 'src', 'vnc_remote_secure', 'config')
    if not os.path.isdir(config_src):
        try:
            from importlib.resources import files
            config_src = str(files('vnc_remote_secure') / 'config')
        except Exception:  # noqa: BLE001
            config_src = ''
    if config_src and os.path.isdir(config_src):
        for filename in os.listdir(config_src):
            src = os.path.join(config_src, filename)
            dst = os.path.join(get_config_dir(), filename)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                logger.info("Copied config: %s", dst)

    # 4. Create the runtime service user.
    create_runtime_user(service_user)

    # 5. Create the temporary remote access user.
    _create_temp_user()

    # 6. Generate SSL certificates if none exist.
    _generate_ssl_certificates()

    # 7. Configure nginx reverse proxy.
    _configure_nginx(project_root)

    # 8. Configure fail2ban.
    _configure_fail2ban()

    # 9. Configure UFW firewall rules.
    _configure_firewall()

    # 10. Install the versioned systemd unit files shipped inside the
    # package. Resolve the post-consolidation path first, then the legacy
    # root-level location, then importlib.resources (pip-installed wheels).
    systemd_candidates = [
        os.path.join(project_root, 'src', 'vnc_remote_secure', 'native', 'linux', 'systemd'),
        os.path.join(project_root, 'native', 'linux', 'systemd'),
    ]
    systemd_src = next((d for d in systemd_candidates if os.path.isdir(d)), '')
    if not systemd_src:
        try:
            from importlib.resources import files

            systemd_src = str(files('vnc_remote_secure') / 'native' / 'linux' / 'systemd')
        except Exception:  # noqa: BLE001
            systemd_src = ''
    systemd_dst = '/etc/systemd/system'
    if systemd_src and os.path.isdir(systemd_src):
        os.makedirs(systemd_dst, exist_ok=True)
        for unit_name in os.listdir(systemd_src):
            if not unit_name.endswith('.service'):
                continue
            src = os.path.join(systemd_src, unit_name)
            dst = os.path.join(systemd_dst, unit_name)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                logger.info("Installed systemd unit: %s", dst)
        # Reload systemd so the new units are recognized.
        install_service('vnc-remote', os.path.join(systemd_dst, 'vnc-remote.service'))
    else:
        logger.error("systemd unit source not found: %s", systemd_src)
        raise FileNotFoundError(
            f"systemd unit templates not found: {systemd_src}. "
            "The package is incomplete; reinstall from a valid release."
        )

    # 11. Set ownership on data/log/run directories.
    for path in (get_data_dir(), get_log_dir(), get_run_dir()):
        try:
            shutil.chown(path, service_user, service_user)
        except (LookupError, OSError) as exc:
            logger.warning("Failed to chown %s to %s: %s", path, service_user, exc)

    logger.info("Linux installation completed successfully.")
    return True


def uninstall(service_user='vnc-remote'):
    """Remove installed files, services, and the runtime user.

    Note: The canonical uninstall flow is in ``core/uninstall.py`` which
    delegates to the platform adapter. This function is retained as a
    platform-specific helper for direct programmatic use.
    """
    from vnc_remote_secure.platform.linux.services import remove_service
    from vnc_remote_secure.platform.linux.users import remove_runtime_user
    remove_service('vnc-remote')
    remove_runtime_user(service_user)

    # Remove nginx site.
    for link in ('/etc/nginx/sites-enabled/vnc-remote-secure',
                 '/etc/nginx/sites-available/vnc-remote-secure'):
        if os.path.exists(link):
            os.remove(link)
            logger.info("Removed nginx site: %s", link)

    # Remove fail2ban configs.
    for path in ('/etc/fail2ban/jail.d/vnc-remote.local',
                 '/etc/fail2ban/filter.d/vnc-remote.conf'):
        if os.path.exists(path):
            os.remove(path)
            logger.info("Removed fail2ban config: %s", path)

    for path in (get_config_dir(), get_data_dir(), get_log_dir()):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    return True
