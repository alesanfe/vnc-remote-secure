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
- Optionally remove configuration files

## Windows

```powershell
.\VncRemote.ps1 Uninstall
```

This will:
- Stop all running services
- Remove Windows Firewall rules
- Remove generated certificates (optional)

## Manual cleanup

If the automated uninstall fails, you can manually clean up:

### Linux
```bash
# Stop services
systemctl stop vnc-remote-*.service

# Remove systemd units
rm /etc/systemd/system/vnc-remote-*.service
systemctl daemon-reload

# Remove configuration
rm -rf /etc/vnc-remote-secure/
rm -rf /var/lib/vnc-remote-secure/
rm -rf /var/log/vnc-remote-secure/
```

### Windows
```powershell
# Remove firewall rules
.\native\windows\Firewall.ps1 -Action Remove

# Remove generated files
Remove-Item -Recurse -Force data\ssl\
Remove-Item -Recurse -Force logs\
```
