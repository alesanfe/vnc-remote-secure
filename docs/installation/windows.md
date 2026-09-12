# Windows Installation

## Prerequisites

- Windows 10/11 (x64)
- Python 3.8+ ([python.org](https://python.org))
- Git for Windows (includes Git Bash)
- UltraVNC (for VNC server)

## Quick Start

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/alex0/vnc-remote-secure.git
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
   Open `https://localhost:8000` in your browser.

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

The installer creates a minimal firewall rule exposing only port 443 (HTTPS):
```powershell
.\native\windows\Firewall.ps1 -Action Create
.\native\windows\Firewall.ps1 -Action List
.\native\windows\Firewall.ps1 -Action Verify
```

## Limitations on Windows

- UltraVNC instead of TigerVNC
- Python/Tornado web terminal instead of ttyd
- Self-signed SSL certificates (no Let's Encrypt)
- No systemd (script-based process management)
- No fail2ban (Windows Defender / Firewall instead)
- No automatic user isolation

## Uninstall

```powershell
.\VncRemote.ps1 Uninstall
```

This stops all services and removes firewall rules.
