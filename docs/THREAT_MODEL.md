# Threat Model

This document presents the formal threat model for the VNC Remote Secure
project. It identifies the assets to protect, applies the STRIDE methodology
to enumerate threats, lists existing and planned controls, states the
security assumptions, and provides a risk matrix.

## System Summary

VNC Remote Secure is a cross-platform system for secure browser-based remote
desktop access. The server runs on Linux or Windows and exposes a web
interface that aggregates a noVNC desktop session, a web terminal, an
optional audio/gamepad stream, and a health dashboard. A Flask user-management
UI handles authentication and session management.

The architecture is package-based: a common Python core
(`src/vnc_remote_secure/`) delegates platform-specific operations to
adapters under `platform/{linux,windows}/`. On Linux, TigerVNC, ttyd, nginx,
and systemd are used; on Windows, UltraVNC, ttyd, and Windows Services are
used. The client requires only a web browser.

The intended deployment topology places nginx as the sole public entry point
(TLS on port 443), with all internal services bound to `127.0.0.1`. Access
from the public internet is expected to traverse TLS; a VPN or SSH tunnel is
recommended for higher-security deployments.

## Assets to Protect

| Asset | Description | Impact if Compromised |
|-------|-------------|----------------------|
| VNC password | Authentication credential for desktop access | Full remote desktop control |
| Terminal credentials | Basic-auth credentials for the web terminal | Remote code execution on the host |
| UI user password | Credential for the Flask user-management UI | Unauthorized service administration |
| SSL/TLS private keys | Private keys for the server certificate | Man-in-the-middle, traffic decryption |
| DuckDNS token | Dynamic DNS API token | DNS hijacking, domain takeover |
| User session | Authenticated browser session cookie | Unauthorized access to services |
| Temporary user account | Linux isolation user for the session | Privilege escalation if misconfigured |
| Configuration file (`.env`) | All credentials and runtime settings | Full system compromise |
| Desktop session | Active VNC framebuffer and input stream | Viewing and control of the desktop |
| System data | Host filesystem and processes accessible via terminal | Data theft, tampering, persistence |

## Threat Model (STRIDE)

### Spoofing

- **Credential theft.** An attacker who obtains the VNC password, terminal
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
- **Terminal injection.** The web terminal forwards input to a shell. Lack
  of input validation or command filtering could allow injection of commands
  beyond the intended scope, leading to host tampering.
- **Configuration tampering.** Modification of `.env`, systemd units, or
  nginx configuration could weaken the security posture silently.

### Repudiation

- **Lack of audit logs.** The current implementation does not produce
  structured, tamper-evident audit logs with session identifiers and
  timestamps. An attacker (or legitimate user) can plausibly deny having
  performed an action because no authoritative record exists.
- **No authenticated action trail.** Login attempts, terminal commands, and
  VNC session start/stop events are not consistently correlated to a user
  identity, weakening accountability.

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

- **Escalation via terminal.** The web terminal grants shell access. A
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
| Session | `HttpOnly`, `SameSite=Lax`, `Secure` cookies; CSRF tokens on state-changing requests |
| Network | nginx as sole public entry point; internal services default to `127.0.0.1`; WebSocket origin validation; Fail2ban integration (Linux); documented firewall guidance |
| User isolation (Linux) | Temporary user created per session and removed on exit by default (`KEEP_TEMP_USER=false`); reserved usernames rejected; `useradd`/`userdel` used for portability |
| System hardening | systemd hardening (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`); secret files with `0600` permissions; `doctor` command validates permissions and configuration |
| Credential handling | No hardcoded credentials; secrets from `.env` or generated at runtime; secrets passed via environment, not command-line args; `.env` gitignored |
| CI/CD | Gitleaks secret scanning; Trivy container/filesystem scanning; ShellCheck; pre-commit hooks preventing secret commits |

## Planned Controls

These controls are recommended but not yet implemented:

- **Centralized authentication.** A single identity and session store shared
  across VNC, terminal, and UI to reduce credential sprawl and enable
  consistent revocation.
- **Multi-factor authentication (MFA).** A second factor for terminal and UI
  access to mitigate credential theft.
- **Rate limiting.** Explicit, configurable rate limits on login attempts
  and WebSocket connection establishment, beyond the current login attempt
  counter.
- **Bind to localhost by default.** Enforce `127.0.0.1` binding for all
  internal services by default, requiring explicit opt-in for any other
  address.
- **WebSocket origin validation.** Strict allow-list-based origin
  validation on every WebSocket endpoint, with rejection of missing or
  unexpected `Origin` headers.
- **Structured audit logging.** Tamper-evident JSON logs with session IDs,
  user identities, timestamps, and action records for logins, terminal
  commands, and session lifecycle events.
- **Session expiration.** TTL-based session revocation and idle timeouts.
- **Content-Security-Policy.** CSP headers for the web UI to mitigate
  injection and data exfiltration.
- **Certificate pinning.** For self-signed deployments to reduce the impact
  of a compromised CA.

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
- Third-party dependencies (TigerVNC, UltraVNC, noVNC, ttyd, nginx, Flask)
  are trusted to behave according to their own security policies; their
  vulnerabilities are reported upstream.
- The VNC protocol's legacy DES authentication is accepted as a known
  limitation and is mitigated by placing VNC behind TLS and restricting
  network exposure.

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
| Lack of audit logs (repudiation) | High | Medium | High | Structured audit logging (planned) |
| Configuration tampering | Low | Critical | High | File permissions, `doctor` validation |
| DNS hijacking (DuckDNS token theft) | Low | High | Medium | Token in gitignored `.env`, Gitleaks |
| TLS misconfiguration | Medium | Medium | Medium | Self-signed with 600 perms, Let's Encrypt option |
| Injection in Flask UI | Low | High | Medium | Input validation, parameterized queries, error sanitization |
| Supply chain (dependency CVEs) | Low | Medium | Low | Trivy, pinned versions, upstream reporting |
