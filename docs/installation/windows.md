# Windows Installation

## Prerequisites

- Windows 10/11 (x64)
- Python 3.11+ ([python.org](https://python.org))
- Git for Windows (includes Git Bash)
- UltraVNC (for VNC server)

  > If UltraVNC is installed in a non-default location, set the
  > `ULTRAVNC_PATH` environment variable to the full path of `winvnc.exe`
  > before running the installer or the CLI. The search order is:
  > `ULTRAVNC_PATH` → `%ProgramFiles%\UltraVNC` → PATH →
  > `<project>\bin\ultravnc\<arch>\` (populated by
  > `tools/download_dependencies.py`).
  >
  > On each start the app renders `ultravnc.ini` next to the resolved
  > `winvnc.exe` — the DES-encrypted `VNC_PASSWORD`, the RFB/HTTP ports,
  > and `QueryAccept=0` so unattended connections are not gated on a
  > console prompt. If the directory is not writable (e.g. a Program
  > Files install under a different admin context), UltraVNC keeps its
  > existing settings — make sure its configured password matches
  > `VNC_PASSWORD` in that case.

## Quick Start

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/alesanfe/vnc-remote-secure.git
   cd vnc-remote-secure
   ```

2. **Install Python dependencies:**
   ```powershell
   pip install -e ".[dev]"
   ```

3. **Configure:**
   ```powershell
   Copy-Item .env.example .env
   # Edit .env with your settings
   ```

4. **Install:**
   ```powershell
   .\VncRemote.ps1 Install
   ```

5. **Start:**
   ```powershell
   .\VncRemote.ps1 Start
   ```

6. **Access:**
   Open `https://127.0.0.1:8000` in your browser.

## Using the unified CLI

After installing the Python package:
```powershell
vnc-remote install
vnc-remote start
vnc-remote status
vnc-remote doctor
vnc-remote stop
vnc-remote uninstall
```

## Windows Firewall

The installer only creates a firewall rule for the **public entry port**
(the landing portal, default 8000) — and only when the deployment is
public-facing (`PUBLIC_BIND_HOST`/`BIND_HOST` is not loopback). A
loopback-only deployment needs no rules at all, and backend service
ports (VNC 5900, noVNC 6080, terminal 5000, health 8090) are never
opened by the installer: on Windows there is no nginx, so opening them
would expose every backend directly, bypassing the auth gateway.

Services bind `127.0.0.1` by default — to expose a service on
the LAN, set its `<SERVICE>_HOST=0.0.0.0` in `config.env` (e.g.
`LANDING_HOST=0.0.0.0`, `SERVE_NOVNC_HOST=0.0.0.0`, `TTYD_HOST=0.0.0.0`,
`HEALTH_WEB_HOST=0.0.0.0`) **and** create the matching rule yourself
(Firewall.ps1 `-Action Create` or `New-NetFirewallRule`). Every service
still enforces the central auth
gateway; `BIND_HOST=0.0.0.0` is refused at startup (Zero Trust). On Linux
with nginx enabled, only port 443 needs to be exposed publicly; the
backend ports should be restricted to the LAN or VPN.
```powershell
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Create
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action List
.\src\vnc_remote_secure\native\windows\Firewall.ps1 -Action Verify
```

## Limitations on Windows

- UltraVNC instead of TigerVNC
- Python/FastAPI web terminal instead of ttyd
- Self-signed SSL certificates (no Let's Encrypt)
- No systemd — a Windows Service (`VncRemoteSecure`) plus the Python
  service manager handle lifecycle instead
- No fail2ban (Windows Defender / Firewall instead)
- No nginx — the landing portal itself is the public entry point.
  Profiles that require `NGINX_ENABLED=true` (`trusted-lan`,
  `private-overlay`, `public-hardened`) cannot be fully satisfied on
  Windows; use `development` or place the host behind a VPN/SSH tunnel.
- Restricted runtime user account (process-level isolation; see ADR-0007)

## Uninstall

```powershell
.\VncRemote.ps1 Uninstall
```

This stops all services and removes firewall rules.
