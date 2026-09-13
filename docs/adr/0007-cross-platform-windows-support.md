# ADR 0007: Cross-platform Windows support with documented limitations

## Status
Accepted

## Context
The project was originally Linux/Raspberry Pi only. The user requested Windows
support for local/LAN access. Windows does not have systemd, apt-get, tigervncserver,
nginx (natively), or ttyd. A full port would require a complete rewrite.

## Decision
Provide a separate Windows launcher (`launch.sh` for Git Bash, now
deprecated in favour of the unified `vnc-remote` CLI) that uses
Windows-native alternatives:
- **UltraVNC** instead of TigerVNC (binary in `bin/ultravnc/`)
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
- `launch.sh` and `launch_nossl.sh` consolidated into one script with `--no-ssl` flag (now deprecated)

## Risks
- Code duplication between Linux and Windows paths
- Windows binaries (UltraVNC) must be managed externally (not in repo)
- Windows security model differs (no user isolation)
- Maintenance burden of two platforms
