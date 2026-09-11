# Threat Model

## Assets

1. **VNC session** - Remote desktop access to the server
2. **Web terminal** - Shell access to the server
3. **Configuration** - Contains credentials and settings
4. **SSL certificates** - Private keys for TLS
5. **User accounts** - Temporary and permanent users on the server

## Threats

### T1: Man-in-the-middle attack
- **Risk**: Attacker intercepts VNC/terminal traffic
- **Mitigation**: All traffic goes through SSL/TLS reverse proxy (nginx)
- **Residual**: Self-signed certs on Windows don't protect against MITM

### T2: Brute force authentication
- **Risk**: Attacker guesses VNC or terminal passwords
- **Mitigation**: Password policy enforcement (min 8 chars, complexity)
- **Mitigation**: fail2ban on Linux (rate limiting + IP ban)
- **Residual**: No fail2ban on Windows

### T3: Direct access to internal services
- **Risk**: Attacker bypasses reverse proxy and accesses services directly
- **Mitigation**: Internal services bind to loopback (127.0.0.1)
- **Mitigation**: Firewall only exposes port 443

### T4: Credential leakage
- **Risk**: Secrets exposed in git, logs, or process list
- **Mitigation**: .env is gitignored, secrets never hardcoded
- **Mitigation**: Passwords generated randomly if not set
- **Mitigation**: Process arguments sanitized

### T5: Privilege escalation
- **Risk**: VNC session user gains root access
- **Mitigation**: Temporary user created with limited permissions
- **Mitigation**: Temp user removed on exit (KEEP_TEMP_USER=false)

### T6: XSS / injection
- **Risk**: Malicious input in username, domain, or other fields
- **Mitigation**: All user input sanitized (HTML escaping)
- **Mitigation**: Username validation (no special characters)
- **Mitigation**: Path traversal prevention

### T7: Certificate theft
- **Risk**: Private key stolen from server
- **Mitigation**: Private keys gitignored, file permissions set to 0600
- **Residual**: On Windows, file permissions are less restrictive

## Attack Surface

| Component | Port | Exposure | Protection |
|-----------|------|----------|------------|
| nginx (HTTPS) | 443 | Public | TLS, security headers |
| Landing page | 8000 | Loopback | nginx proxy |
| noVNC | 6080 | Loopback | nginx proxy, WebSocket |
| Terminal | 5000 | Loopback | nginx proxy, auth |
| Health | 8090 | Loopback | nginx proxy |
| VNC | 5900 | Loopback | Not proxied directly |

## Security Boundaries

```
Internet
  │
  ▼
[Firewall: only port 443]
  │
  ▼
[nginx: TLS termination, auth, rate limiting]
  │
  ├── / ──────► Landing page (127.0.0.1:8000)
  ├── /vnc/ ──► noVNC/websockify (127.0.0.1:6080)
  ├── /term/ ─► ttyd/tornado (127.0.0.1:5000)
  └── /health/► Health server (127.0.0.1:8090)
```
