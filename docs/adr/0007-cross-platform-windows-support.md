# ADR 0007: Cross-platform Windows support with documented limitations

## Status
Accepted

## Context
The project was originally Linux/Raspberry Pi only. The user requested Windows
support for local/LAN access. Windows does not have systemd, apt-get, tigervncserver,
nginx (natively), or a native ttyd build. A full port would require a complete rewrite.

## Decision
Provide a separate Windows launcher (`launch.sh` for Git Bash, now
deprecated in favour of the unified `vnc-remote` CLI) that uses
Windows-native alternatives:
- **UltraVNC** instead of TigerVNC (auto-provisioned by the Windows
  installer when not already installed; externally-installed copies and
  the `ULTRAVNC_PATH` env var are still honoured)
- **Tornado web terminal** instead of ttyd (avoids ConPTY issues on Windows 11)
- **websockify** (Python, cross-platform) for noVNC proxy
- **Python health server** with Windows-native metrics (wmic, systeminfo)
- **Python landing page** (same as Linux)
- **Self-signed certificates** instead of Let's Encrypt (certbot not available on Windows)

Windows is explicitly documented as "local/LAN support, not full parity":
- No systemd (processes managed by script or Windows Services)
- No fail2ban (Windows Firewall instead)
- No Let's Encrypt (self-signed certs only)
- User isolation via dedicated restricted runtime account (implemented)
- No session recording

## Alternatives considered
1. **Windows-native rewrite (PowerShell/C#)**: Rejected — duplicates all logic.
2. **WSL2 only**: Run Linux version inside WSL2.
   Rejected — WSL2 doesn't support VNC display access natively.
3. **Docker on Windows**: Containerize the Linux version.
   Considered but rejected for VNC display access reasons.
4. **No Windows support**: Linux only.
   Rejected — user explicitly requested Windows support.

## Consequences
- Two launch paths: `src/rpi-vnc-remote.sh` (Linux) and `vnc-remote` (unified CLI, replaces deprecated `launch.sh`)
- Some features are Linux-only (documented in README)
- Windows users need Git Bash + Python 3.11+ + UltraVNC binaries
- `launch.sh` and the removed `launch_nossl.sh` are consolidated into the unified `vnc-remote` CLI with `--no-ssl` flag (`launch.sh` itself is deprecated)

## Risks
- Code duplication between Linux and Windows paths
- Windows binaries (UltraVNC) are auto-provisioned by the installer from
  the official release; the `ULTRAVNC_URL` env var can override the
  download source. Externally-installed copies and `ULTRAVNC_PATH` are
  still honoured as fallbacks.
- **Process-level isolation is incomplete**: The restricted runtime user
  is created and ACLs are applied to data directories, but VNC and
  terminal processes currently run under the current user's context, not
  under the restricted user. Full process impersonation
  (CreateProcessAsUser) is a planned enhancement.
- **Service runs as LocalSystem**: `sc.exe create` does not pass an
  `obj=` logon account, so `VncRemoteSecure` runs under the default
  LocalSystem context — more privilege than required. A virtual service
  account (`NT SERVICE\VncRemoteSecure`) plus ACL grants on
  `%ProgramData%\VncRemoteSecure` is the planned hardening.
- Maintenance burden of two platforms
