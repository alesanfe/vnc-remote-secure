"""Legacy .env migration — the shared implementation behind
``vnc-remote config migrate`` and ``POST /api/v1/config/migrate``.

Both transports preview (``dry_run``) or apply the same renames so a
UI-triggered migration produces byte-identical results to the CLI.
"""
import contextlib
import os
import tempfile

# (old, new, message) — key renames are whole-KEY matches; value
# renames only rewrite the SECURITY_PROFILE value.
MIGRATIONS = [
    ('VNC_REMOTE_PROFILE', 'SECURITY_PROFILE',
     'VNC_REMOTE_PROFILE is deprecated, use SECURITY_PROFILE'),
    ('CERT_FILE', 'SSL_CERT',
     'CERT_FILE is deprecated, use SSL_CERT'),
    ('KEY_FILE', 'SSL_KEY',
     'KEY_FILE is deprecated, use SSL_KEY'),
    ('NOVNC_HOST', 'SERVE_NOVNC_HOST',
     'NOVNC_HOST is deprecated, use SERVE_NOVNC_HOST'),
    ('home-lan', 'trusted-lan',
     'Profile home-lan renamed to trusted-lan'),
    ('private-vpn', 'private-overlay',
     'Profile private-vpn renamed to private-overlay'),
    ('internet-hardened', 'public-hardened',
     'Profile internet-hardened renamed to public-hardened'),
    ('local-only', 'development',
     'Profile local-only renamed to development'),
]


def _migrate_env_line(ln, var_migrations, value_migrations, changes,
                      dry_run):
    """Migrate one .env line; record each change in ``changes``."""
    stripped = ln.strip()
    if not stripped or stripped.startswith('#') or '=' not in ln:
        return ln
    key, _, val = ln.partition('=')
    key_s, val_s = key.strip(), val.strip()
    for old, new, msg in var_migrations:
        if key_s == old:
            changes.append({'old': old, 'new': new, 'message': msg})
            if not dry_run:
                ln = ln.replace(key, key.replace(old, new), 1)
            break
    for old, new, msg in value_migrations:
        # Check both the current key and the legacy key it may be
        # renamed FROM in this same pass — a renamed
        # VNC_REMOTE_PROFILE line must still get its profile value
        # migrated.
        if key_s in ('SECURITY_PROFILE', 'VNC_REMOTE_PROFILE') \
                and val_s == old:
            changes.append({'old': old, 'new': new, 'message': msg})
            if not dry_run:
                ln = ln.replace(val, val.replace(old, new), 1)
            break
    return ln


def migrate_env(env_path: str | None = None, dry_run: bool = False):
    """Migrate legacy variable names/values in the project .env.

    Returns ``{'changes': [...], 'applied': bool, 'env_path': str}``.
    ``dry_run=True`` reports the changes without writing. Raises
    ``FileNotFoundError`` when no .env exists.
    """
    if env_path is None:
        # Late lookup so tests can monkeypatch core.paths.find_project_root.
        from vnc_remote_secure.core import paths
        env_path = os.path.join(paths.find_project_root(), '.env')
    if not os.path.exists(env_path):
        raise FileNotFoundError(f'No .env file at {env_path}')
    with open(env_path, encoding='utf-8') as f:
        lines = f.read().splitlines()

    # Key-aware migration: a plain substring replace would corrupt
    # variables that merely CONTAIN the legacy name (e.g.
    # ``MY_CERT_FILE`` → ``MY_SSL_CERT``). Keys are renamed only when
    # they appear as the whole KEY before ``=``; value aliases are
    # rewritten only inside the SECURITY_PROFILE value.
    var_migrations = [
        (o, n, m) for o, n, m in MIGRATIONS
        if '=' not in o and o.isupper()
        and o.replace('_', '').isalpha()]
    value_migrations = [
        (o, n, m) for o, n, m in MIGRATIONS
        if (o, n) not in {(a, b) for a, b, _ in var_migrations}]

    out_lines, changes = [], []
    for ln in lines:
        out_lines.append(
            _migrate_env_line(ln, var_migrations, value_migrations,
                              changes, dry_run))

    applied = bool(changes) and not dry_run
    if applied:
        content = '\n'.join(out_lines) + '\n'
        # Atomic write: a crash mid-write of the .env in place would
        # lose every other variable — same treatment as
        # set_env_persistent().
        from vnc_remote_secure.core.test_isolation import guard_write
        guard_write(env_path, 'config migrate')
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(env_path) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            os.replace(tmp, env_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    return {'changes': changes, 'applied': applied, 'env_path': env_path}
