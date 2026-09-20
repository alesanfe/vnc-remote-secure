#!/usr/bin/env python3
"""
Migrate configuration from old format to new package-based format.

This tool is a thin wrapper around the canonical migration logic in
``vnc-remote config migrate``. It delegates to the CLI to perform:

- Renaming deprecated environment variables (VNC_REMOTE_PROFILE → SECURITY_PROFILE,
  CERT_FILE → SSL_CERT, KEY_FILE → SSL_KEY, etc.)
- Renaming old security profile aliases (home-lan, private-vpn, etc.)

It also checks for deprecated launch scripts. Note that the CLI's
``config migrate`` command performs string replacements of deprecated
names and profile aliases; it does not validate against the JSON schema
or normalize TLS flags. Run ``vnc-remote config validate`` separately
to validate the resulting configuration.

Usage:
    python tools/migrate_configuration.py
    # or equivalently:
    vnc-remote config migrate
"""
import os
import subprocess
import sys


def find_project_root():
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(current, '.env.example')):
            return current
        current = os.path.dirname(current)
    return os.getcwd()


def check_old_scripts(project_root):
    """Check for deprecated scripts and warn."""
    deprecated = [
        ('launch.sh', 'Deprecated delegator. Use: vnc-remote start'),
        ('src/rpi-vnc-remote.sh',
         'Legacy compatibility wrapper. Prefer: vnc-remote'),
    ]
    for script, replacement in deprecated:
        path = os.path.join(project_root, script)
        if os.path.exists(path):
            print(f"[WARN] {script} is deprecated. {replacement}")
    return True


def run_cli_migrate(project_root):
    """Delegate to ``vnc-remote config migrate`` for canonical migration."""
    print("[INFO] Running: vnc-remote config migrate")
    env = os.environ.copy()
    src_dir = os.path.join(project_root, 'src')
    env['PYTHONPATH'] = src_dir + os.pathsep + env.get('PYTHONPATH', '')
    result = subprocess.run(
        [sys.executable, '-m', 'vnc_remote_secure.cli', 'config', 'migrate'],
        cwd=project_root,
        env=env,
    )
    return result.returncode == 0


def main():
    project_root = find_project_root()
    print("=== VNC Remote Secure - Configuration Migration ===")
    print(f"Project root: {project_root}")
    print()

    # Check for deprecated scripts first.
    check_old_scripts(project_root)

    # Delegate to the canonical CLI migration.
    ok = run_cli_migrate(project_root)

    print()
    if ok:
        print("[PASS] Migration complete")
        print("       Run 'vnc-remote config validate' to verify.")
        return 0
    else:
        print("[FAIL] Migration failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
