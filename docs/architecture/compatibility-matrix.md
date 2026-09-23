# Linux / Windows compatibility matrix

Every feature, what backs it on each platform, and its real
limitations. "Parity" here means equivalent *capability* — the
implementation differs per OS by design (platform adapters).

| Feature | Linux | Windows | Notes / limitations |
|---------|-------|---------|---------------------|
| VNC server | TigerVNC (`Xtigervnc`) | UltraVNC (`winvnc.exe`) | Legacy DES auth on both — 8-char password, loopback-only + relay |
| Browser desktop (noVNC) | ✅ | ✅ | Same websockify bridge + RFB filter |
| RFB input filter (view-only) | ✅ | ✅ | Protocol-level; identical |
| Web terminal | Tornado executor | Tornado executor | No PTY either side (ConPTY deliberately avoided); `WEBTERM_SHELL` allowlist |
| Terminal resource limits | process groups + SIGKILL tree | Job Objects (`KILL_ON_JOB_CLOSE`) | Windows uses `taskkill /T` fallback |
| Audio streaming | ffmpeg (`-f pulse`/alsa) | ffmpeg (`-f dshow`) | Per-device availability varies |
| Gamepad forwarding | uinput via `evdev` (real virtual device) | `SendInput` key/mouse injection (ctypes) | **Not parity**: Windows injects keyboard/mouse events, not an XInput gamepad — games expecting a controller won't see one. Real XInput needs ViGEmBus (third-party driver) — not bundled |
| Systemd / service mode | `vnc-remote.service` unit | Windows Service (SCM) | Both supervised by the same service manager |
| Process cleanup | process groups (`setsid` + `killpg`) | `CREATE_NEW_PROCESS_GROUP` + Job Objects | Orphan grandchildren reaped on both |
| PID-reuse-safe kill | ✅ start-time + cmdline identity | ✅ same check | `--force` bypass exists on both |
| Firewall | ufw / iptables helpers | Windows Firewall (netsh/PowerShell) | Rule names differ, semantics equal |
| Secret file protection | POSIX `0o600` | icacls owner-only ACL | Verified by `secrets check`/`doctor` on both |
| Shared state | SQLite | SQLite | Same file-lock + WAL semantics |
| Audit log | ✅ | ✅ | Same chain/seq/mirror |
| TLS certs | self-signed, certbot (Let's Encrypt) | self-signed | **LE issuance is Linux-only** (certbot); Windows: import a PFX or use Caddy/Win-ACME externally |
| DuckDNS | ✅ | ✅ | Pure HTTPS update — platform-agnostic |
| nginx reverse proxy | ✅ | optional | Template ships for Linux; Windows deployments typically expose services directly or use another front |
| fail2ban | ✅ | — | Windows equivalent: rate-limit lockouts already in-app |
| Ephemeral share links | ✅ | ✅ | Same store + propagation |
| Operator MFA (TOTP) | ✅ | ✅ | Same replay protection |
| Portal control surface | ✅ | ✅ | Sessions list/revoke/revoke-all, backups, cert days |
| Watchdog + auto-restart | ✅ | ✅ | Same throttling |
| Metrics (Prometheus) | ✅ | ✅ | Same endpoint |
| Alerts (Discord/webhook/email) | ✅ | ✅ | Same dispatch |
| Temp restricted user | `vnc-remote` system user | restricted local user | **Windows limitation**: VNC/terminal run in the *caller's* session — a service account can't capture the interactive desktop (Session 0 isolation). See `windows-session-model.md` |
| Screen capture before login | ✅ (Xvnc virtual display possible) | ❌ Session-0 can't see the interactive console | Windows needs the console session active; locked screens capture but UAC secure desktop may not |
| Upgrade + rollback | ✅ | ✅ | `vnc-remote upgrade` — pip-based on both |
| Installers | `.deb` skeleton + install.sh | WiX/winget manifests | Native installer builds are pipeline work — `packaging/` has manifests, not yet signed binaries |

## Reading the matrix

- **✅** — implemented and tested on that platform (unit/e2e where CI
  allows; Windows-only paths are covered by unit tests with mocked
  Win32 calls plus manual verification).
- **Limitations are features' real edges**, not bugs — anything
  marked "not parity" is a documented architectural constraint with
  a reason attached.
