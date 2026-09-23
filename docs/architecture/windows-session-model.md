# Windows session architecture

How the services map onto Windows sessions — and why full process
isolation is a documented limitation, not a bug.

## The Session-0 constraint (correctly stated)

On modern Windows (Vista+), **Session 0 is reserved for services** —
it has no interactive desktop and cannot capture the user's screen.
The interactive user session is a *separate* session (typically
Session 1+). Any process that captures the desktop must therefore
run **inside the interactive session**, which means:

- UltraVNC runs as the interactive user — a Windows Service in
  Session 0 cannot capture that user's screen.
- Terminal/VNC processes cannot run as the restricted runtime user
  for capture purposes — a different user's session is unreachable.

```text
Session 0 (services)                Session N (interactive user)
┌─────────────────────────┐         ┌──────────────────────────────┐
│  Windows Service         │         │  winvnc.exe (UltraVNC)        │
│  (vnc-remote service     │  PID    │   └ captures THIS session     │
│   manager watchdog)      ├────────►│  Tornado web terminal         │
│                          │ spawn   │   └ AppContainer sandbox      │
│  shared_state.db is NOT  │         │  ffmpeg audio capture         │
│  readable from Session N │         │  ViGEm gamepad injector       │
└─────────────────────────┘         └──────────────────────────────┘
         ▲
         │ CLI (same user, foreground or service context)
         v
   vnc-remote start / stop / watchdog
```

## What IS isolated

- **Web terminal** — child shells spawn inside an **AppContainer**
  (`platform/windows/sandbox.py`, `TERMINAL_WINDOWS_SANDBOX=auto`).
  The sandboxed shell cannot read the user profile holding
  `auth_secret.key`, `shared_state.db`, or generated credentials.
- **State files** — run-dir ACLs restrict to owner+SYSTEM; the
  restricted runtime user never gets read access to secrets.
- **Privileges** — no process runs elevated by design; UltraVNC is
  launched unprivileged inside the session.

## What is NOT isolated (documented limitation, F-035/ADR-0007)

- UltraVNC shares the interactive user's token — it can read what
  the user can read. Full impersonation (CreateProcessAsUser) is a
  tracked enhancement.
- Only the *active* console session is capturable: fast-user
  switching to another account loses the VNC view until the session
  is re-established (UltraVNC's own service mode handles re-logon
  when installed as a service).
- The secure desktop (UAC prompts) is not capturable/controllable —
  standard limitation of user-mode VNC servers.

## Multi-user behaviour

- One interactive session at a time is served — the session that
  owns the console when UltraVNC starts.
- `service --run` under a Windows Service keeps the manager in
  Session 0; the spawned VNC/terminal processes are created in the
  console session via the user-context launch path.
