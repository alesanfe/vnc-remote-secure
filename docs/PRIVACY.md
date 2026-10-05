# Privacy — VNC Remote Secure

A remote-access tool is inherently sensitive: it can see and control
the host desktop. This document states what data the system processes
and where it lives.

## Design stance

- **Local-first**: all state lives on the host under `data/` — no
  external service is required for core functionality.
- **No telemetry**: the software does not phone home. No analytics,
  crash reporting, or usage beacons.
- **Outbound calls are user-initiated**: dependency downloads
  (`tools/download_dependencies.py`) and optional dynamic DNS /
  upgrade checks — each is explicit and documented.

## Data inventory

| Data | Where | Sensitivity | Retention |
|---|---|---|---|
| Credentials (VNC, UI, operator) | `.env` / OS stores; hashed or encrypted at rest | high | user-controlled |
| Sessions & tokens | `data/` via shared_state | high | ephemeral + explicit expiry |
| Audit log | `data/` (append-only events) | medium | rotation policy |
| Session recordings `.vrsrec` | host disk, operator-triggered | high | user-controlled deletion |
| Backups | `backups/` | high (contains config) | user-controlled |
| Share links | fragment-URL tokens — never reach the server | medium | auto-expire |

## What is NOT collected

- Screen content is never sent anywhere except the authenticated
  browser session of the connecting user.
- No third-party SDKs, trackers, or fonts loaded remotely in the SPA.
- Recordings are opt-in and stay on the host.

## User responsibilities

- Serve only over HTTPS/VPN/SSH tunnel — VNC's DES auth is a legacy
  protocol limitation (see `AGENTS.md` security rules).
- Treat `backups/` and recordings as secrets: they can contain config
  and desktop content.
