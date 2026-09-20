# Upgrade Guide

How to upgrade an existing VNC Remote Secure installation to a newer version.

## Prerequisites

- Python 3.11+
- Git (for source upgrades)
- Existing installation of VNC Remote Secure
- Sudo/root access (for system service changes)

## Pre-upgrade checks

```bash
# Check the current version
vnc-remote version

# Verify the system is healthy
vnc-remote doctor

# Create a backup of the current configuration and data
vnc-remote backup
```

## Method 1: Git-based upgrade (recommended)

```bash
cd /path/to/vnc-remote-secure

# Pull the latest changes
git pull --ff-only

# Reinstall the package in editable mode (picks up new dependencies)
pip install -e ".[dev]"

# Re-run install to apply any new system configuration
sudo vnc-remote install

# Restart all services
vnc-remote restart

# Verify the new version and health
vnc-remote version
vnc-remote status
```

## Method 2: Archive-based upgrade

```bash
# Download the new release archive
wget https://github.com/alesanfe/vnc-remote-secure/archive/refs/tags/vX.Y.Z.zip
unzip vX.Y.Z.zip
cd vnc-remote-secure-X.Y.Z

# Install dependencies
pip install -e ".[dev]"

# Apply system configuration
sudo vnc-remote install

# Restart services
vnc-remote restart
```

## Post-upgrade verification

```bash
# Confirm the new version is running
vnc-remote version

# Run the doctor to check system readiness
vnc-remote doctor

# Check service status
vnc-remote status

# Validate the configuration
vnc-remote config validate
```

## Configuration migration

If the release includes configuration changes, run the migration tool:

```bash
# Migrate deprecated variables and aliases
vnc-remote config migrate

# Review the effective configuration
vnc-remote config show-effective

# Diff two profiles
vnc-remote config diff --profile-a <profile-a> --profile-b <profile-b>
```

## Rollback

If the upgrade fails or causes issues:

```bash
# Stop the new version
vnc-remote stop

# Restore the backup created before the upgrade
vnc-remote backup --list    # list available backups
vnc-remote restore <backup-name>

# If you upgraded via git, check out the previous tag
git checkout vX.Y.W
pip install -e ".[dev]"
sudo vnc-remote install
vnc-remote restart
```

## Windows upgrade

```powershell
# Pull the latest source
git pull --ff-only

# Reinstall the Python package
pip install -e ".[dev]"

# Re-apply the Windows configuration
.\VncRemote.ps1 Install

# Restart the service
.\VncRemote.ps1 Restart

# Verify
.\VncRemote.ps1 Get-Status
```

## Notes

- The `vnc-remote backup` command creates a tarball under `backups/`
  containing configuration, secrets, and service state.
- Configuration defaults live in `src/vnc_remote_secure/config/defaults/{common,linux,windows}.env`
  and are loaded automatically by the Python runtime.
- The systemd unit (`src/vnc_remote_secure/native/linux/systemd/vnc-remote.service`) runs the
  Python service manager in foreground mode via `vnc-remote service --run`.
