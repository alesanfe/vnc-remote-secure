# Platform adapter contracts

The domain layer (`services/`, `security/`, `core/`) must never
contain `os.name`/platform conditionals — platform differences live
behind the adapters in `platform/{linux,windows}/`. This document is
the contract every adapter (current or future, e.g. macOS) must
satisfy.

## Contract levels

| Level | Meaning |
|-------|---------|
| **Required** | The method is called unconditionally; `NotImplementedError` propagates as a startup failure. |
| **Optional** | May return `None`/empty/`False` — the caller degrades the feature, never crashes. |
| **Fail-closed** | Must NOT silently succeed. Errors surface as `ServiceError`/`RuntimeError`, never `return False` on a security-relevant operation. |

## `platform/base.py::PlatformAdapter`

| Method | Level | Contract |
|--------|-------|----------|
| `remove_service(name)` | Required | Idempotent — succeeds when the service is already gone. |
| `remove_firewall_rule(rule_name)` | Required | Idempotent; matches by the name `install_firewall_rule` assigned. |
| `install_firewall_rule(port, proto, rule_name)` | Required | Creates a **named** rule so removal is deterministic; returns `True`/`False`. |
| `create_runtime_user(username)` | Fail-closed | Creates the least-privilege runtime account; existing account is success; failure raises. |
| `remove_runtime_user(username)` | Required | Idempotent. |
| `get_platform_info()` | Required | Dict — must include `system`, `release`, `hostname`, plus platform extras. |
| `get_lan_ips()` | Optional | List of non-loopback IPv4s; `[]` acceptable when undetectable. |
| `start_vnc_server(display, geometry, depth, password)` | Fail-closed | Returns a process object with `.pid`; raises `ServiceError` when the binary is missing or the server dies immediately. The **caller** owns lifecycle (PID file, process group/Job Object) — the adapter must not daemonize away control. |
| `get_audio_capture_cmd(ffmpeg, device, bitrate)` | Optional | argv list for ffmpeg input; `None` = audio unsupported. |
| `list_audio_devices(ffmpeg)` | Optional | List of device names; `[]` when none. |
| `create_gamepad_injector()` | Optional | Injector object with `inject_button`/`inject_axis`/`close`, or `None` when the platform lacks the mechanism — the gamepad service then refuses connections instead of half-working. |

## Sibling modules (uniform across adapters)

| Module | Contract |
|--------|----------|
| `installer.py` | `install()`/`uninstall()` idempotent — second `install` on a configured system is a no-op update, never a wipe. Privilege escalation happens inside, never assumed. |
| `permissions.py` | `create_user`, `remove_user`, `user_exists`, `set_user_password`, `list_users`, `restrict_user` — least privilege by default; no shell/login unless required. |
| `services.py` | `detect_services()` returns the service table the manager supervises — names, commands, ports, `internal` flags. |
| `metrics.py` | `get_metrics()` → dict for the portal/health pages; keys may differ per platform, missing keys render as `N/A`. |
| `firewall.py` (Windows) | Windows-specific rule helpers; Linux folds this into the adapter. |
| `sandbox.py` (Windows) | Job Object creation/assignment — POSIX adapters use process groups instead and don't need this module. |
| `users.py` | Platform OS-account adapters behind `/api/v1/system-users` — the React admin console manages runtime accounts through them; there is no server-rendered user UI. |

## Non-negotiable rules for new adapters

1. **No raw secrets across the boundary.** Passwords go through
   `set_user_password`/file descriptors, never argv (ps-visible).
2. **Idempotency everywhere.** Install, firewall rules, users,
   services — safe to run twice.
3. **Fail-closed on security operations.** A sandbox/permission
   failure aborts; "best effort" is only acceptable for pure
   telemetry (metrics, LAN IP discovery).
4. **The adapter owns OS mechanics, the domain owns policy.** E.g.
   the adapter runs `netsh`; the *decision* to open a port comes
   from config/domain code.
5. **Testability.** Every subprocess/ctypes call goes through a
   seam (`_powershell.py`, `run_cmd`, injectable `which`) so unit
   tests never need the real OS.
6. **Capability reporting beats version sniffing.** Return `None`/
   empty when a feature is unavailable — let the caller degrade,
   don't fake success.
