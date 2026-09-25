"""``config`` command: show-effective, validate, diff, migrate."""
import json


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


def _config_explain(args):
    """Explain how one variable resolves: value, source, precedence."""
    from vnc_remote_secure.core.config_inspector import compute_effective_config

    name = args.var_name.upper()
    profile = getattr(args, 'profile', None)
    effective = compute_effective_config(profile_name=profile)
    entry = next((e for e in effective if e['name'] == name), None)
    if entry is None:
        print(f"Unknown config variable: {name}")
        return 1
    if args.json:
        print(json.dumps(entry, indent=2))
    else:
        print(f"{entry['name']} = {entry['value']}")
        print(f"  source: {entry['source']}")
        print("  precedence: hardcoded-default < platform-default "
              "< profile < .env < env")
        if entry['source'] == 'security-policy':
            print("  note: value enforced by the security profile — "
                  "cannot be overridden")
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
    """Migrate legacy config values to current format — delegates to
    ``core.config_migration`` (the same implementation the
    ``/api/v1/config/migrate`` route uses)."""
    from vnc_remote_secure.core.config_migration import migrate_env

    try:
        result = migrate_env(dry_run=args.dry_run)
    except FileNotFoundError:
        print("No .env file found.")
        return 1
    changes = result['changes']
    if not changes:
        print("No migrations needed — config is already up to date.")
        return 0
    if args.dry_run:
        print("Dry run — the following changes would be made:")
        for c in changes:
            print(f"  {c['old']} -> {c['new']}: {c['message']}")
        return 0
    print("Applied migrations:")
    for c in changes:
        print(f"  {c['old']} -> {c['new']}: {c['message']}")
    return 0


def cmd_config(args):
    """Manage configuration (show-effective, validate, diff, migrate)."""
    from vnc_remote_secure.core.config import load_env_file

    load_env_file()

    actions = {
        'show-effective': _config_show_effective,
        'explain': _config_explain,
        'validate': _config_validate,
        'diff': _config_diff,
        'migrate': _config_migrate,
    }
    handler = actions.get(args.config_action)
    if handler is None:
        print(f"Unknown config action: {args.config_action}")
        return 1
    return handler(args)
