# Uninstall

## Linux

```bash
# Using the CLI
vnc-remote uninstall

# Or using the maintenance script
bash scripts/maintenance/uninstall.sh
```

This will:
- Stop all VNC Remote Secure services
- Remove systemd unit files
- Remove firewall rules
- Remove configuration, data, logs, runtime and SSL directories

Pass `--keep-data` to preserve configuration, data, logs, SSL
certificates and backups (services and installed files are still
removed):

```bash
vnc-remote uninstall --keep-data
```

## Windows

```powershell
.\VncRemote.ps1 Uninstall                # removes data (same as CLI)
.\VncRemote.ps1 Uninstall --keep-data    # preserves config/data/logs/ssl
```

The standalone script `native/windows/commands/Uninstall-VncRemote.ps1`
inverts the default: it keeps data unless `-RemoveData` is passed.

This will:
- Stop all running services
- Remove the Windows Service registration (`VncRemoteSecure`)
- Remove Windows Firewall rules
- Remove the runtime user and generated certificates (optional)

> **Note:** third-party software is never removed automatically.
> UltraVNC (auto-provisioned to `%ProgramFiles%\UltraVNC` by the
> installer when missing) is left in place — remove it separately
> through Windows "Apps & Features" if no longer needed. The same
> applies on Linux to apt packages (TigerVNC, ttyd, nginx, certbot)
> installed by `vnc-remote install`.

## Manual cleanup

If the automated uninstall fails, you can manually clean up:

### Linux
```bash
# Stop services
systemctl stop vnc-remote.service

# Remove systemd unit
rm /etc/systemd/system/vnc-remote.service
systemctl daemon-reload

# Remove configuration
rm -rf /etc/vnc-remote-secure/
rm -rf /var/lib/vnc-remote-secure/
rm -rf /var/log/vnc-remote-secure/
```

### Windows
```powershell
# Remove firewall rules
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Remove

# Remove generated files
Remove-Item -Recurse -Force data\ssl\
Remove-Item -Recurse -Force logs\
```
