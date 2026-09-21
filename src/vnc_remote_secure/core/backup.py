"""Backup and restore for VNC Remote Secure.

Creates and restores tar.gz backups of configuration, SSL certificates,
and runtime state. This is the canonical Python implementation that
replaces the legacy ``scripts/maintenance/backup.sh`` and
``restore.sh`` Bash scripts so the CLI no longer delegates to Bash.

Backups can be encrypted using AES-128-CBC (Fernet) when the
``BACKUP_PASSWORD`` environment variable is set. Encrypted backups
use the ``.enc.tar.gz`` extension and contain a Fernet token blob.
When ``BACKUP_PASSWORD`` is unset, backups remain plaintext (with a
warning logged).
"""
import base64
import hashlib
import logging
import os
import shutil
import tarfile
import time
from typing import Optional

from vnc_remote_secure.core.paths import (
    find_project_root,
    get_config_dir,
    get_data_dir,
    get_run_dir,
    get_ssl_dir,
)

logger = logging.getLogger(__name__)

# Restore-time bounds: a tar-bomb would otherwise fill the disk
# during extraction. Generous ceilings — real backups contain config,
# certs and state files, far below these limits.
_MAX_BACKUP_MEMBERS = 10000
_MAX_BACKUP_FILE_SIZE = 512 * 1024 * 1024      # 512 MiB per member
_MAX_BACKUP_TOTAL_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB uncompressed

# Bumped when the archive layout changes incompatibly. Restore warns
# (but still attempts) when a backup reports a newer format.
_BACKUP_FORMAT_VERSION = 1


def _get_backup_key(salt: bytes = None, iterations: int = 600000):
    """Return a Fernet key derived from BACKUP_PASSWORD, or None.

    PBKDF2-HMAC-SHA256 with a random per-backup salt — a bare
    SHA-256(password) digest is a fast, salt-free brute-force target
    for anyone holding an encrypted backup. ``salt=None`` reproduces
    the legacy unsalted derivation so old backups still restore.
    """
    password = os.environ.get('BACKUP_PASSWORD', '')
    if not password:
        return None
    if salt is None:
        # Legacy format: SHA-256(password) — kept for restoring backups
        # created before PBKDF2 was introduced.
        digest = hashlib.sha256(password.encode('utf-8')).digest()
    else:
        digest = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, iterations)
    return base64.urlsafe_b64encode(digest)


_PBKDF2_ITERATIONS = 600000
_SALT_LEN = 16


def _encrypt_file(source_path, dest_path):
    """Encrypt a file using Fernet (requires cryptography).

    The output format is ``salt(16B) || fernet_token`` so each backup
    derives its key under a different salt.
    """
    import secrets as _secrets

    from cryptography.fernet import Fernet
    salt = _secrets.token_bytes(_SALT_LEN)
    key = _get_backup_key(salt=salt, iterations=_PBKDF2_ITERATIONS)
    if key is None:
        raise ValueError("BACKUP_PASSWORD not set")
    fernet = Fernet(key)
    with open(source_path, 'rb') as f:
        data = f.read()
    token = fernet.encrypt(data)
    with open(dest_path, 'wb') as f:
        f.write(salt + token)


def _decrypt_file(source_path, dest_path):
    """Decrypt a Fernet-encrypted file.

    Tries the salted PBKDF2 format first (``salt || token``), then the
    legacy unsalted derivation for backups created by older versions.
    """
    from cryptography.fernet import Fernet, InvalidToken
    password = os.environ.get('BACKUP_PASSWORD', '')
    if not password:
        raise ValueError("BACKUP_PASSWORD not set")
    with open(source_path, 'rb') as f:
        blob = f.read()
    # New format: first _SALT_LEN bytes are the PBKDF2 salt.
    if len(blob) > _SALT_LEN:
        salt, token = blob[:_SALT_LEN], blob[_SALT_LEN:]
        key = _get_backup_key(salt=salt, iterations=_PBKDF2_ITERATIONS)
        try:
            data = Fernet(key).decrypt(token)
            with open(dest_path, 'wb') as f:
                f.write(data)
            return
        except InvalidToken:
            pass  # fall through to the legacy derivation
    key = _get_backup_key()
    data = Fernet(key).decrypt(blob)
    with open(dest_path, 'wb') as f:
        f.write(data)


def _backup_dir() -> str:
    """Return the backups directory (under the project root)."""
    d = os.path.join(find_project_root(), 'backups')
    os.makedirs(d, exist_ok=True)
    # Backups hold secrets (.env, SSL keys, signing secret) — the
    # directory must not be group/world-accessible on POSIX. On
    # Windows chmod only toggles the read-only flag, so this is a
    # no-op there and the dir inherits the project ACL.
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _collect_paths() -> list:
    """Return the list of (source, archive_name) pairs to back up."""
    paths = []
    project_root = find_project_root()

    # .env file
    env_file = os.path.join(project_root, '.env')
    if os.path.isfile(env_file):
        paths.append((env_file, '.env'))

    # System config.env seeded by the installer (Windows: ProgramData
    # root, Linux: /etc/vnc-remote-secure) — distinct from the project
    # .env and the config/ directory, and easy to miss.
    from vnc_remote_secure.platform.detection import is_windows
    sys_cfg = (os.path.join(
                   os.environ.get('ProgramData', r'C:\ProgramData'),
                   'VncRemoteSecure', 'config.env')
               if is_windows()
               else '/etc/vnc-remote-secure/config.env')
    if os.path.isfile(sys_cfg):
        paths.append((sys_cfg, 'system-config.env'))

    # SSL certificates (platform-aware)
    ssl_dir = get_ssl_dir()
    if os.path.isdir(ssl_dir):
        paths.append((ssl_dir, os.path.basename(ssl_dir)))

    # Config directory
    config_dir = get_config_dir()
    if os.path.isdir(config_dir):
        paths.append((config_dir, 'config'))

    # Data directory (excluding logs)
    data_dir = get_data_dir()
    if os.path.isdir(data_dir):
        paths.append((data_dir, 'data'))

    # Runtime secrets whose loss would silently invalidate every issued
    # token/session or regenerate credentials the operator never saw:
    # the signing secret, persisted auto-generated credentials, and the
    # ephemeral session store. shared_state.db is included too — it is
    # the durable record of consumed recovery codes, used TOTP
    # timesteps, and WebSocket revocations; restoring .env without it
    # would un-burn one-time credentials (replay). Only truly volatile
    # state (pids, sockets) is excluded.
    run_dir = get_run_dir()
    for name in ('auth_secret.key', 'generated_credentials.env',
                 'ephemeral_sessions.json', 'instance.id',
                 'shared_state.db'):
        p = os.path.join(run_dir, name)
        if os.path.isfile(p):
            paths.append((p, f'run/{name}'))

    return paths


def create_backup(output: Optional[str] = None) -> str:
    """Create a tar.gz backup of configuration and certificates.

    Also saves the current service-manager state (PIDs) so it can be
    restored later.

    Args:
        output: Optional output path. When ``None`` a timestamped
            filename is created in the ``backups/`` directory.

    Returns:
        The path to the created backup file.
    """
    # Load the effective env first: BACKUP_PASSWORD lives in
    # .env/config.env — without this an operator-configured password
    # would be invisible and the backup would be written UNENCRYPTED
    # (a silent security downgrade).
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    # Save service-manager state alongside the backup.
    try:
        from vnc_remote_secure.core.service_manager import save_state
        state = save_state()
    except Exception as e:
        logger.debug("Could not save service state: %s", e)
        state = {'pids': {}, 'timestamp': time.time()}

    if output is None:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        ext = '.enc.tar.gz' if _get_backup_key() else '.tar.gz'
        output = os.path.join(_backup_dir(), f'backup_{timestamp}{ext}')

    paths = _collect_paths()
    if not paths:
        logger.warning("No files to back up")
        return output

    # Create the tar.gz to a temporary path first, then encrypt if needed.
    tmp_tar = output if not _get_backup_key() else output + '.tmp'
    with tarfile.open(tmp_tar, 'w:gz') as tar:
        import io
        import json as _json
        # Format manifest: restore uses it to warn on incompatible or
        # unexpectedly new backup formats instead of guessing.
        try:
            from vnc_remote_secure import __version__ as _app_ver
        except Exception:  # noqa: BLE001
            _app_ver = 'unknown'
        manifest = {
            'format_version': _BACKUP_FORMAT_VERSION,
            'created': time.time(),
            'app_version': _app_ver,
        }
        man_bytes = _json.dumps(manifest, indent=2).encode('utf-8')
        man_info = tarfile.TarInfo(name='backup-manifest.json')
        man_info.size = len(man_bytes)
        man_info.mtime = time.time()
        tar.addfile(man_info, io.BytesIO(man_bytes))
        # Include the service-manager state as a JSON file in the archive.
        state_bytes = _json.dumps(state, indent=2).encode('utf-8')
        state_info = tarfile.TarInfo(name='service_state.json')
        state_info.size = len(state_bytes)
        state_info.mtime = time.time()
        tar.addfile(state_info, io.BytesIO(state_bytes))
        for src, arcname in paths:
            if os.path.exists(src):
                tar.add(src, arcname=arcname, recursive=True,
                        filter=lambda info: None if info.name.endswith('.log') else info)

    # Encrypt if BACKUP_PASSWORD is set.
    if _get_backup_key():
        try:
            _encrypt_file(tmp_tar, output)
            os.unlink(tmp_tar)
            # The archive contains secrets even when encrypted —
            # owner-only read like every other credential file.
            try:
                os.chmod(output, 0o600)
            except OSError:
                pass
            logger.info("Encrypted backup created: %s", output)
        except Exception as e:
            # The operator asked for encryption by setting
            # BACKUP_PASSWORD — leaving a plaintext archive of secrets
            # behind would silently defeat that intent. Fail loudly
            # and remove the unencrypted intermediate instead.
            try:
                os.unlink(tmp_tar)
            except OSError:
                pass
            raise RuntimeError(
                f"Backup encryption failed — no plaintext backup was "
                f"kept: {e}") from e
    else:
        logger.warning(
            "BACKUP_PASSWORD not set — backup is unencrypted and contains "
            "secrets (.env, SSL keys). Store it securely."
        )
        # Owner-only: the plaintext archive holds .env, SSL keys and
        # the auth signing secret — the default umask would leave it
        # world-readable on Linux.
        try:
            os.chmod(output, 0o600)
        except OSError:
            pass
        logger.info("Backup created: %s", output)
    return output


def restore_backup(backup_file: str, dry_run: bool = False) -> bool:
    """Restore a backup tar.gz to the appropriate system locations.

    Args:
        backup_file: Path to the backup tar.gz file.
        dry_run: When ``True``, fully decrypt, validate and extract the
            archive but skip the copy phase — nothing on disk is
            modified. Useful to verify a backup is restorable before
            committing to it.

    Returns:
        ``True`` if the restore (or the dry-run validation) completed
        successfully.
    """
    if not os.path.isfile(backup_file):
        raise FileNotFoundError(f"Backup file not found: {backup_file}")

    # Load the effective env first: BACKUP_PASSWORD lives in
    # .env/config.env — needed to decrypt .enc.tar.gz backups.
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()

    project_root = find_project_root()
    temp_dir = os.path.join(project_root, 'backups', '_restore_tmp')
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)

    # Determine if the backup is encrypted.
    is_encrypted = backup_file.endswith('.enc.tar.gz')
    actual_tar = backup_file
    decrypted_tar = None

    if is_encrypted:
        if not _get_backup_key():
            raise RuntimeError(
                "Backup is encrypted but BACKUP_PASSWORD is not set. "
                "Set BACKUP_PASSWORD to restore this backup."
            )
        decrypted_tar = os.path.join(temp_dir, '_decrypted.tar.gz')
        _decrypt_file(backup_file, decrypted_tar)
        actual_tar = decrypted_tar

    try:
        with tarfile.open(actual_tar, 'r:gz') as tar:
            # Validate each member to prevent path traversal (absolute paths,
            # '..' components) before extracting. Also bound the archive:
            # member count, per-file size and total uncompressed size —
            # a tar-bomb would otherwise fill the disk during extraction.
            members = tar.getmembers()
            if len(members) > _MAX_BACKUP_MEMBERS:
                raise RuntimeError(
                    f"Backup has too many entries "
                    f"({len(members)} > {_MAX_BACKUP_MEMBERS})"
                )
            total_size = 0
            for member in members:
                member_path = os.path.normpath(member.name)
                if member_path.startswith('..') or os.path.isabs(member_path):
                    raise RuntimeError(
                        f"Unsafe path in backup archive: {member.name}"
                    )
                # Resolve and ensure it stays within temp_dir.
                target = os.path.realpath(os.path.join(temp_dir, member_path))
                if not target.startswith(os.path.realpath(temp_dir) + os.sep):
                    raise RuntimeError(
                        f"Unsafe path in backup archive: {member.name}"
                    )
                if member.size > _MAX_BACKUP_FILE_SIZE:
                    raise RuntimeError(
                        f"Backup member too large: {member.name} "
                        f"({member.size} > {_MAX_BACKUP_FILE_SIZE})"
                    )
                total_size += member.size
            if total_size > _MAX_BACKUP_TOTAL_SIZE:
                raise RuntimeError(
                    f"Backup uncompressed size too large "
                    f"({total_size} > {_MAX_BACKUP_TOTAL_SIZE})"
                )
            # 'data' filter additionally blocks symlink/hardlink members
            # whose targets escape temp_dir — the name checks above do
            # not cover link payloads. filter= exists on 3.12+ (and
            # backported 3.11.x); fall back to the manual checks.
            try:
                tar.extractall(temp_dir, filter='data')
            except TypeError:
                tar.extractall(temp_dir)
    except tarfile.TarError as e:
        raise RuntimeError(f"Failed to extract backup: {e}")

    # Format manifest: warn (not fail) on a newer format — forward
    # compatibility is best-effort; a missing manifest means the
    # backup predates format versioning.
    manifest_path = os.path.join(temp_dir, 'backup-manifest.json')
    if os.path.isfile(manifest_path):
        try:
            import json as _json
            with open(manifest_path, encoding='utf-8') as f:
                manifest = _json.load(f)
            fmt = int(manifest.get('format_version', 0))
            if fmt > _BACKUP_FORMAT_VERSION:
                logger.warning(
                    "Backup format v%s is newer than supported v%s — "
                    "restoring anyway, some members may be ignored",
                    fmt, _BACKUP_FORMAT_VERSION)
            else:
                logger.info(
                    "Backup format v%s (created by v%s)",
                    fmt, manifest.get('app_version', 'unknown'))
        except (ValueError, OSError) as e:
            logger.warning("Unreadable backup manifest: %s", e)

    if dry_run:
        logger.info("Dry run: backup validated and extracted; "
                    "no files were modified")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return True

    try:
        # Restore .env
        env_src = os.path.join(temp_dir, '.env')
        if os.path.isfile(env_src):
            shutil.copy2(env_src, os.path.join(project_root, '.env'))

        # Restore the system config.env captured as 'system-config.env'
        # (Windows: ProgramData root; Linux: /etc/vnc-remote-secure).
        sys_cfg_src = os.path.join(temp_dir, 'system-config.env')
        if os.path.isfile(sys_cfg_src):
            from vnc_remote_secure.platform.detection import is_windows
            sys_cfg_dst = (os.path.join(
                               os.environ.get('ProgramData', r'C:\ProgramData'),
                               'VncRemoteSecure', 'config.env')
                           if is_windows()
                           else '/etc/vnc-remote-secure/config.env')
            try:
                os.makedirs(os.path.dirname(sys_cfg_dst), exist_ok=True)
                shutil.copy2(sys_cfg_src, sys_cfg_dst)
            except OSError as e:
                logger.warning("Could not restore system config.env: %s", e)

        # Restore SSL certs
        ssl_dir = get_ssl_dir()
        for name in ('ssl', os.path.basename(get_ssl_dir())):
            src = os.path.join(temp_dir, name)
            if os.path.isdir(src):
                os.makedirs(ssl_dir, exist_ok=True)
                for item in os.listdir(src):
                    s = os.path.join(src, item)
                    d = os.path.join(ssl_dir, item)
                    if os.path.isfile(s):
                        shutil.copy2(s, d)

        # Restore config (recursive — subdirectories are preserved)
        config_dst = get_config_dir()
        config_src = os.path.join(temp_dir, 'config')
        if os.path.isdir(config_src):
            shutil.copytree(config_src, config_dst, dirs_exist_ok=True)

        # Restore data (recursive — the data dir can contain nested state
        # such as the ssl/ subdirectory on XDG layouts)
        data_dst = get_data_dir()
        data_src = os.path.join(temp_dir, 'data')
        if os.path.isdir(data_src):
            shutil.copytree(data_src, data_dst, dirs_exist_ok=True)

        # Restore runtime secrets (auth secret, generated credentials,
        # ephemeral session store) captured under 'run/'.
        run_dst = get_run_dir()
        run_src = os.path.join(temp_dir, 'run')
        if os.path.isdir(run_src):
            os.makedirs(run_dst, exist_ok=True)
            for item in os.listdir(run_src):
                s = os.path.join(run_src, item)
                if os.path.isfile(s):
                    shutil.copy2(s, os.path.join(run_dst, item))

        # Restore service-manager state (PIDs) if available in the extracted archive.
        try:
            from vnc_remote_secure.core.service_manager import restore_state
            state_file = os.path.join(temp_dir, 'service_state.json')
            if os.path.isfile(state_file):
                import json
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                restore_state(state)
        except Exception as e:
            logger.debug("Could not restore service state: %s", e)

        # Re-apply restrictive permissions on restored secrets — on Windows
        # tar member modes are meaningless, so restored keys/config would
        # inherit the directory's default ACLs (readable by Users) and get
        # flagged by validate_secret_files().
        try:
            from vnc_remote_secure.security.certificates import (
                _restrict_key_permissions,
            )
            restored_secrets = [
                os.path.join(project_root, '.env'),
            ]
            if os.path.isfile(sys_cfg_src):
                restored_secrets.append(sys_cfg_dst)
            for base in (ssl_dir, config_dst, data_dst, run_dst):
                if not os.path.isdir(base):
                    continue
                for root, _dirs, files in os.walk(base):
                    for item in files:
                        if item.lower().endswith(('.pem', '.key', '.env')) \
                                or item in ('config.env', 'auth_secret.key',
                                            'ephemeral_sessions.json',
                                            'instance.id',
                                            'shared_state.db'):
                            restored_secrets.append(os.path.join(root, item))
            for f in restored_secrets:
                if os.path.isfile(f):
                    _restrict_key_permissions(f, writable=True)
        except Exception as e:  # noqa: BLE001
            logger.debug("Could not restrict restored file permissions: %s", e)

    except OSError as e:
        logger.error("Restore failed: %s — partial files may have been "
                     "copied; check permissions on the target directories.", e)
        return False
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    logger.info("Backup restored from: %s", backup_file)
    return True


def list_backups() -> list:
    """Return a list of available backup files (newest first).

    Includes both plaintext (``.tar.gz``) and encrypted
    (``.enc.tar.gz``) backups.
    """
    d = _backup_dir()
    backups = [os.path.join(d, f) for f in os.listdir(d)
               if f.startswith('backup_') and (f.endswith('.tar.gz') or f.endswith('.enc.tar.gz'))]
    backups.sort(key=os.path.getmtime, reverse=True)
    return backups


def verify_backup(backup_file: str) -> tuple:
    """Verify a backup archive's integrity without restoring it.

    Decrypts (when encrypted) into a temp file and iterates every tar
    member, reading each entry to force CRC/decompression errors to
    surface. Returns ``(ok, message, member_count)`` — ``member_count``
    is ``-1`` on failure.
    """
    if not os.path.isfile(backup_file):
        return False, f'Backup not found: {backup_file}', -1

    tar_path = backup_file
    tmp = None
    try:
        if backup_file.endswith('.enc.tar.gz'):
            import tempfile
            fd, tmp = tempfile.mkstemp(suffix='.tar.gz')
            os.close(fd)
            try:
                _decrypt_file(backup_file, tmp)
            except Exception as e:  # noqa: BLE001 - bad password/format
                return False, f'Decryption failed: {e}', -1
            tar_path = tmp

        count = 0
        with tarfile.open(tar_path, 'r:gz') as tar:
            for member in tar.getmembers():
                count += 1
                if member.isfile():
                    f = tar.extractfile(member)
                    if f is not None:
                        # Read fully — forces gzip CRC validation of
                        # this member's data blocks.
                        while f.read(65536):
                            pass
        return True, f'Archive intact ({count} members)', count
    except (tarfile.TarError, OSError, EOFError) as e:
        return False, f'Archive corrupt: {e}', -1
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
