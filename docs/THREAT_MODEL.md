# Threat Model

This document presents the formal threat model for the VNC Remote Secure
project. It identifies the assets to protect, applies the STRIDE methodology
to enumerate threats, lists existing and planned controls, states the
security assumptions, and provides a risk matrix.

## System Summary

VNC Remote Secure is a cross-platform system for secure browser-based remote
desktop access. The server runs on Linux or Windows and exposes a web
interface that aggregates a noVNC desktop session, a web terminal, an
optional audio/gamepad stream, and a health dashboard. All browser-facing
UI is a single React SPA (public portal at `/`, operator console at
`/admin/*`, share/audio/gamepad/terminal pages) served by the FastAPI
portal; authentication and session management go through the versioned
`/api/v1/*` API (`vnc_op` operator cookie + `vnc_csrf`/X-CSRF-Token,
`vnc_ephemeral` share-session cookie, step-up auth for destructive ops).

The architecture is package-based: a common Python core
(`src/vnc_remote_secure/`) delegates platform-specific operations to
adapters under `platform/{linux,windows}/`. On Linux, TigerVNC, a
FastAPI/uvicorn-based web terminal, nginx, and systemd are used; on Windows,
UltraVNC, the same FastAPI web terminal, and Windows Services are used.
The client requires only a web browser.

The intended deployment topology places nginx as the sole public entry point
(TLS on port 443), with all internal services bound to `127.0.0.1`. Access
from the public internet is expected to traverse TLS; a VPN or SSH tunnel is
recommended for higher-security deployments.

## Assets to Protect

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| VNC password | Authentication credential for desktop access | Full remote desktop control |
| Web Terminal credentials | Basic-auth credentials for the Web Terminal | Remote code execution on the host |
| Operator credential | Password/passkey for the admin console (`vnc_op` session) | Unauthorized service administration |
| SSL/TLS private keys | Private keys for the server certificate | Man-in-the-middle, traffic decryption |
| DuckDNS token | Dynamic DNS API token | DNS hijacking, domain takeover |
| User session | Authenticated browser session cookie | Unauthorized access to services |
| Temporary user account | Linux isolation user for the session | Privilege escalation if misconfigured |
| Configuration file (`.env`) | All credentials and runtime settings | Full system compromise |
| Desktop session | Active VNC framebuffer and input stream | Viewing and control of the desktop |
| System data | Host filesystem and processes accessible via terminal | Data theft, tampering, persistence |

## Threat Model (STRIDE)

### Spoofing

- **Credential theft.** An attacker who obtains the VNC password, Web Terminal
  credentials, or UI password can impersonate a legitimate user. The VNC
  protocol uses legacy DES authentication with an 8-character password
  limit, which materially reduces the effective key space.
- **Identity spoofing via the UI.** Without a centralized identity provider
  or multi-factor authentication, a stolen password is sufficient to assume
  the user's identity across all components.

### Tampering

- **Session tampering.** Modification of session cookies or CSRF tokens
  could allow an attacker to inject or elevate a session. Session integrity
  relies on cookie flags and signed tokens.
- **Web Terminal injection.** The Web Terminal forwards input to a shell. Lack
  of input validation or command filtering could allow injection of commands
  beyond the intended scope, leading to host tampering.
- **Configuration tampering.** Modification of `.env`, systemd units, or
  nginx configuration could weaken the security posture silently.

### Repudiation

- **Audit logging (implemented).** Structured, tamper-evident audit logs
  with session identifiers and timestamps are produced by
  `security/audit.py`. Login attempts, terminal commands, and VNC session
  lifecycle events are correlated to a user identity via the central
  authentication gateway. The audit log uses a SHA-256 chain hash for
  tamper detection (see `verify_chain()`).

### Information Disclosure

- **Secrets in logs.** Passwords and tokens could be exposed in console
  output, log files, or error messages if redaction is bypassed or a new
  code path logs them inadvertently.
- **VNC without encryption.** If VNC is exposed without TLS (noVNC
  `--ssl-only` disabled, or direct VNC port exposure), the framebuffer and
  credentials traverse the network in cleartext.
- **Process argument disclosure.** Passing secrets as command-line
  arguments would expose them via the process list (`ps`, Task Manager).
- **Health endpoint disclosure.** The health endpoint may leak version or
  configuration details if it is not bound to localhost or if its response
  is too verbose.

### Denial of Service

- **WebSocket connection exhaustion.** The noVNC and terminal WebSocket
  endpoints may accept unbounded concurrent connections, exhausting file
  descriptors or memory.
- **Brute force.** Without rate limiting, an attacker can attempt unlimited
  password guesses against the VNC, terminal, or UI login.
- **Resource exhaustion.** A single long-lived session or a flood of
  authentication requests can consume CPU and memory on a constrained host
  (e.g., a Raspberry Pi).

### Elevation of Privilege

- **Escalation via Web Terminal.** The Web Terminal grants shell access. A
  misconfiguration or an overly permissive temporary user could allow
  escalation to root or another system user.
- **Temporary user misuse.** If `KEEP_TEMP_USER=true` is set or the
  temporary user is not removed on exit, the account persists and may become
  a stepping stone for privilege escalation.
- **Service account over-privilege.** If services run as root or
  Administrator instead of a least-privilege account, a compromise of any
  service yields full host control.

## Existing Controls

| Layer | Controls |
|-------|----------|
| Transport | SSL/TLS with self-signed or Let's Encrypt certificates; noVNC `--ssl-only` when SSL is enabled; HTTPS for the web terminal and UI |
| Authentication | Required VNC password (hashed); web terminal basic auth; UI session-based auth with CSRF protection; strong password validation rejecting defaults (`changeme`, `admin123`, etc.); constant-time comparison via `hmac.compare_digest` |
| Session | `HttpOnly`, `Secure` cookies; `SameSite=Strict` for operator cookies (`vnc_op`, `vnc_csrf`, `vnc_session`); the ephemeral `vnc_ephemeral` cookie follows `SESSION_SAMESITE`; CSRF tokens on state-changing requests |
| Network | nginx as sole public entry point; internal services default to `127.0.0.1`; WebSocket origin validation; Fail2ban integration (Linux); documented firewall guidance |
| User isolation (Linux) | Temporary user created per session and removed on exit by default (`KEEP_TEMP_USER=false`); reserved usernames rejected; `useradd`/`userdel` used for portability |
| System hardening | systemd hardening (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`); secret files with `0600` permissions; `doctor` command validates permissions and configuration |
| Credential handling | No hardcoded credentials; secrets from `.env` or generated at runtime; secrets passed via environment, not command-line args; `.env` gitignored |
| CI/CD | Gitleaks secret scanning; Trivy container/filesystem scanning; ShellCheck; pre-commit hooks preventing secret commits |

## Implemented Controls (v0.2.0)

The following controls, previously planned, are now implemented:

- **Centralized authentication.** A unified authentication gateway with MFA/TOTP
  support shared across VNC, terminal, and UI (`security/auth_gateway.py`).
- **Multi-factor authentication (MFA).** TOTP-based second factor for terminal
  and UI access (`security/step_up_auth.py`).
- **Rate limiting.** Configurable rate limits on login attempts and WebSocket
  connection establishment (`security/rate_limit.py`).
- **Bind to localhost by default.** Internal services default to `127.0.0.1`
  binding; security profiles enforce this in hardened modes
  (`security/profiles.py`).
- **WebSocket origin validation.** Strict allow-list-based origin validation
  on WebSocket endpoints with rejection of missing or unexpected `Origin`
  headers (`services/terminal.py`).
- **Structured audit logging.** Tamper-evident JSON logs with session IDs, user
  identities, timestamps, and action records (`security/audit.py`).
- **Session expiration.** TTL-based session revocation and idle timeouts
  (`security/ephemeral_sessions.py`).
- **Content-Security-Policy.** CSP headers for the web UI to mitigate
  injection and data exfiltration (`security/http_headers.py`).

## Planned Controls

These controls are recommended but not yet implemented:

- **Certificate pinning.** For self-signed deployments to reduce the impact
  of a compromised CA.
- **Full Windows process isolation.** The restricted runtime user is created
  and ACLs are applied, but VNC and terminal processes do not yet run under
  the restricted user's context (CreateProcessAsUser is planned; see ADR-0007).

## Security Assumptions

- The host operating system is kept patched and is not already compromised.
- The operator follows documented configuration guidance and does not
  intentionally weaken defaults (e.g., binding to `0.0.0.0` or disabling
  SSL).
- `.env` and secret files are protected by filesystem permissions and are
  never committed to version control.
- The network path between client and server is trusted only up to TLS;
  beyond TLS, the operator is responsible for additional controls (VPN,
  firewall).
- Physical access to the host is restricted and out of scope.
- Third-party dependencies (TigerVNC, UltraVNC, noVNC, ttyd, nginx,
  FastAPI/uvicorn, the React/Vite frontend toolchain) are trusted to
  behave according to their own security policies; their
  vulnerabilities are reported upstream.
- The VNC protocol's legacy DES authentication is accepted as a known
  limitation and is mitigated by placing VNC behind TLS and restricting
  network exposure.
- **View-only sessions now filter RFB input at the protocol layer.**
  A `--view-only` ephemeral session blocks the control channels
  (gamepad requires `desktop:control`, terminal honours
  `no_terminal`, clipboard/file transfer are separate permissions)
  and the `/websockify` relay activates `services.rfb_filter`, which
  parses the client RFB stream inside WebSocket frames and drops
  KeyEvent(4)/PointerEvent(5)/ClientCutText(6) messages. Unknown RFB
  message types close the connection (fail closed). Note the filter
  applies to ephemeral sessions through the authenticated WS
  endpoint; direct RFB access to the VNC server port is a separate
  channel (bind it to loopback or use a view-only VNC password).

## Risk Matrix

Risk is rated as the product of likelihood (L) and impact (I), each on a
three-level scale (Low, Medium, High). The resulting risk level is
classified as Low, Medium, High, or Critical.

| Threat | Likelihood | Impact | Risk | Primary Controls |
|--------|-----------|--------|------|------------------|
| VNC/terminal credential theft | Medium | High | High | Strong password validation, TLS, bind localhost |
| Brute force (VNC/terminal/UI) | Medium | High | High | Rate limiting, Fail2ban, constant-time comparison |
| Session hijacking | Low | High | Medium | HttpOnly, SameSite, Secure, CSRF tokens |
| Cross-Site WebSocket hijacking | Low | High | Medium | Origin header validation |
| Secret leakage in logs | Medium | Critical | Critical | Redaction, Gitleaks, no secret logging |
| Secret leakage in process list | Low | High | Medium | Secrets from env/files, not args |
| VNC without encryption (misconfiguration) | Medium | Critical | Critical | `--ssl-only`, nginx TLS, documented guidance |
| Health endpoint information disclosure | Low | Low | Low | Bind localhost, minimal response |
| WebSocket connection exhaustion (DoS) | Medium | Medium | Medium | Connection limits (planned), bind localhost |
| Privilege escalation via terminal | Low | Critical | High | Temp user isolation, systemd hardening, least privilege |
| Temporary user persistence / misuse | Low | Critical | High | `KEEP_TEMP_USER=false`, cleanup on exit |
| Lack of audit logs (repudiation) | High | Medium | High | Structured audit logging (implemented, `security/audit.py`) |
| Configuration tampering | Low | Critical | High | File permissions, `doctor` validation |
| DNS hijacking (DuckDNS token theft) | Low | High | Medium | Token in gitignored `.env`, Gitleaks |
| TLS misconfiguration | Medium | Medium | Medium | Self-signed with 600 perms, Let's Encrypt option |
| Injection via admin SPA / `/api/v1` | Low | High | Medium | CSRF gate (`vnc_csrf` + X-CSRF-Token), Origin/Sec-Fetch-Site checks, per-route capability gating, step-up auth, input validation, error sanitization |
| Supply chain (dependency CVEs) | Low | Medium | Low | Trivy, pinned versions, upstream reporting |
