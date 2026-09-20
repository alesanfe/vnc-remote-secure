"""``config`` command: show-effective, validate, diff, migrate."""
import json
import os

from vnc_remote_secure.cli._common import _find_project_root


def _config_show_effective(args):
    """Show the effective configuration for a profile."""
    from vnc_remote_secure.core.config_inspector import compute_effective_config

    profile = getattr(args, 'profile', None)
    effective = compute_effective_config(profile_name=profile)
    if args.json:
        print(json.dumps(effective, indent=2))
    else:
        print(f"{'Variable':<30} {'Value':<30} {'Source'}")
        print(f"{'-' * 30} {'-' * 30} {'-' * 20}")
        for entry in effective:
            print(f"{entry['name']:<30} {entry['value']:<30} {entry['source']}")
    return 0


def _config_validate(args):
    """Validate the configuration for a profile."""
    from vnc_remote_secure.core.config_inspector import validate_config

    profile = getattr(args, 'profile', None)
    findings = validate_config(profile_name=profile)
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        if not findings:
            print("Configuration is valid.")
        else:
            for f in findings:
                sev = f['severity'].upper()
                print(f"  [{sev}] {f['message']}")
    criticals = [f for f in findings if f['severity'] == 'critical']
    return 1 if criticals else 0


def _config_diff(args):
    """Show the diff between two profile configurations."""
    from vnc_remote_secure.core.config_inspector import (
        compute_effective_config,
        diff_configs,
    )

    config_a = compute_effective_config(profile_name=args.profile_a)
    config_b = compute_effective_config(profile_name=args.profile_b)
    diffs = diff_configs(config_a, config_b)
    if args.json:
        print(json.dumps(diffs, indent=2))
    else:
        if not diffs:
            print(f"No differences between '{args.profile_a}' and '{args.profile_b}'.")
        else:
            print(f"{'Variable':<30} {'A':<20} {'B':<20}")
            print(f"{'-' * 30} {'-' * 20} {'-' * 20}")
            for d in diffs:
                print(f"{d['name']:<30} {d['value_a']:<20} {d['value_b']:<20}")
    return 0


def _config_migrate(args):
    """Migrate legacy config values to current format."""
    # Migrate legacy config values to current format.
    migrations = [
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
    changes = []
    env_path = os.path.join(_find_project_root(), '.env')
    if not os.path.exists(env_path):
        print("No .env file found.")
        return 1
    with open(env_path, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()

    # Key-aware migration: a plain substring replace would corrupt
    # variables that merely CONTAIN the legacy name (e.g.
    # ``MY_CERT_FILE`` → ``MY_SSL_CERT``). Keys are renamed only when
    # they appear as the whole KEY before ``=``; value aliases are
    # rewritten only inside the SECURITY_PROFILE value.
    var_migrations = [(o, n, m) for o, n, m in migrations
                      if '=' not in o and o.isupper() and o.replace('_', '').isalpha()]
    value_migrations = [(o, n, m) for o, n, m in migrations
                        if (o, n) not in {(a, b) for a, b, _ in var_migrations}]
    out_lines = []
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith('#') or '=' not in ln:
            out_lines.append(ln)
            continue
        key, _, val = ln.partition('=')
        key_s, val_s = key.strip(), val.strip()
        for old, new, msg in var_migrations:
            if key_s == old:
                changes.append({'old': old, 'new': new, 'message': msg})
                if not args.dry_run:
                    ln = ln.replace(key, key.replace(old, new), 1)
                break
        for old, new, msg in value_migrations:
            # Check both the current key and the legacy key it may be
            # renamed FROM in this same pass — a renamed
            # VNC_REMOTE_PROFILE line must still get its profile value
            # migrated.
            if key_s in ('SECURITY_PROFILE', 'VNC_REMOTE_PROFILE') and val_s == old:
                changes.append({'old': old, 'new': new, 'message': msg})
                if not args.dry_run:
                    ln = ln.replace(val, val.replace(old, new), 1)
                break
        out_lines.append(ln)
    if not args.dry_run and changes:
        content = '\n'.join(out_lines) + '\n'
    if not changes:
        print("No migrations needed — config is already up to date.")
        return 0
    if args.dry_run:
        print("Dry run — the following changes would be made:")
        for c in changes:
            print(f"  {c['old']} -> {c['new']}: {c['message']}")
    else:
        # Atomic write: a crash mid-write of the .env in place would
        # lose every other variable — same treatment as
        # set_env_persistent().
        import tempfile
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(env_path) or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            os.replace(tmp, env_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        print("Applied migrations:")
        for c in changes:
            print(f"  {c['old']} -> {c['new']}: {c['message']}")
    return 0


def cmd_config(args):
    """Configuration management (show-effective, validate, diff, migrate)."""
    from vnc_remote_secure.core.config import load_env_file

    load_env_file()

    actions = {
        'show-effective': _config_show_effective,
        'validate': _config_validate,
        'diff': _config_diff,
        'migrate': _config_migrate,
    }
    handler = actions.get(args.config_action)
    if handler is None:
        print(f"Unknown config action: {args.config_action}")
        return 1
    return handler(args)
