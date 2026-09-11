#!/usr/bin/env python3
"""
Migrate configuration from old format to new package-based format.

Handles:
- Moving .env to config/ structure
- Updating paths in configuration
- Migrating from old launch scripts to vnc-remote CLI
"""
import os
import sys
import shutil
import json


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def migrate_env_file(project_root):
    """Migrate .env to new config structure."""
    old_env = os.path.join(project_root, '.env')
    new_env = os.path.join(project_root, 'config', 'local.env')

    if not os.path.exists(old_env):
        print("[SKIP] No .env file found")
        return True

    if os.path.exists(new_env):
        print(f"[SKIP] {new_env} already exists")
        return True

    os.makedirs(os.path.dirname(new_env), exist_ok=True)
    shutil.copy2(old_env, new_env)
    print(f"[OK] Migrated .env -> config/local.env")
    print("     You can now remove the old .env file")
    return True


def check_old_scripts(project_root):
    """Check for deprecated scripts and warn."""
    deprecated = [
        ('launch_nossl.sh', 'Use: vnc-remote start --profile local'),
        ('kill_all.sh', 'Use: vnc-remote stop --force'),
    ]
    for script, replacement in deprecated:
        path = os.path.join(project_root, script)
        if os.path.exists(path):
            print(f"[WARN] {script} is deprecated. {replacement}")
    return True


def validate_config_schema(project_root):
    """Validate configuration against schema if available."""
    schema_path = os.path.join(project_root, 'config', 'schema', 'config.schema.json')
    env_path = os.path.join(project_root, '.env')

    if not os.path.exists(schema_path):
        print("[SKIP] No config schema found")
        return True

    if not os.path.exists(env_path):
        print("[SKIP] No .env file to validate")
        return True

    try:
        import jsonschema
    except ImportError:
        print("[SKIP] jsonschema not installed, skipping validation")
        return True

    with open(schema_path) as f:
        schema = json.load(f)

    # Parse .env into dict
    config = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            val = val.strip().strip('"\'')
            # Type coercion based on schema
            if key in schema.get('properties', {}):
                prop = schema['properties'][key]
                if prop.get('type') == 'integer':
                    try:
                        val = int(val)
                    except ValueError:
                        pass
                elif prop.get('type') == 'boolean':
                    val = val.lower() in ('true', '1', 'yes')
            config[key] = val

    try:
        jsonschema.validate(config, schema)
        print("[OK] Configuration validates against schema")
    except jsonschema.ValidationError as e:
        print(f"[FAIL] Configuration validation error: {e.message}")
        return False

    return True


def main():
    project_root = find_project_root()
    print(f"=== VNC Remote Secure - Configuration Migration ===")
    print(f"Project root: {project_root}")
    print()

    steps = [
        migrate_env_file,
        check_old_scripts,
        validate_config_schema,
    ]

    all_ok = True
    for step in steps:
        if not step(project_root):
            all_ok = False

    print()
    if all_ok:
        print("[PASS] Migration checks complete")
        return 0
    else:
        print("[FAIL] Some migration checks failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
