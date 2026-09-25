# Trust boundaries

Every boundary where untrusted input crosses into the system, what
authenticates it, and what happens on failure. "Hostile" means
attacker-controlled input is expected by design.

| # | Boundary | Protocol | Auth | Crypto | Limits | Failure mode |
|---|----------|----------|------|--------|--------|--------------|
| 1 | Browser → nginx (public) | HTTPS/WSS | session cookie / ephemeral | TLS | nginx timeouts, conn cap | 4xx, no backend touch |
| 2 | Browser → service (direct, no nginx) | HTTP/WS | same + Origin check | TLS per profile | BoundedThreading* semaphore + read timeout | 401/403, rate-limit |
| 3 | nginx → backend service | HTTP/WS | loopback + forwarded headers (TRUSTED_PROXY only) | optional TLS | proxy limits | 502/503 |
| 4 | noVNC → websockify bridge | TCP | loopback only — never public | none (loopback) | relay idle timeout | close |
| 5 | websockify → RFB server | TCP | loopback + DES password (8-char, secondary) | none (loopback) | RFB filter caps buffer | drop+close |
| 6 | terminal ws → child shell | pipes | step-up + permission `terminal` | n/a | sandbox (bwrap/AppContainer), sanitized env, output caps | SIGKILL group |
| 7 | any service → shared_state.db | sqlite | filesystem ACL (owner-only) | at-rest OS perms | busy_timeout, WAL | fail closed |
| 8 | portal → ephemeral exchange | URL fragment `#t=` → POST `/api/v1/session/{preview,activate}` | single-use token signature | TLS per profile | token TTL, IP/resource bind | 403, token burned |
| 9 | alerts → Discord/webhook/email | HTTPS | webhook URL/secret | TLS | timeout, no secrets in payload | drop+log |
| 10 | CLI → config/.env | file | filesystem ACL | n/a | schema validate, unknown keys warn | refuse start (hardened) |
| 11 | restore → backup file | file | BACKUP_PASSWORD (Fernet/PBKDF2) | AES-128-CBC | tar path/link sanitization | refuse, no partial write |
| 12 | runtime → DuckDNS | HTTPS | DuckDNS token | TLS | interval cap | warn, retry |

## Rules encoded by the boundary table

- **Boundary 4/5 are absolute**: the websockify bridge and RFB port
  must never listen off-loopback. `doctor` verifies this at runtime
  (`security.public_listeners` check) and hardened profiles refuse
  to start with public backend binds.
- **Boundary 3 trusts forwarded headers only under `TRUSTED_PROXY`** —
  a direct client can spoof `X-Forwarded-*`; headers are honoured
  only when the flag is set.
- **Boundary 8 burns the token on use** — the token crosses in the
  URL fragment (`/share#t=`), which browsers never send to the
  server; the SPA wipes it and posts it in the request body to
  `session/preview`/`session/activate`. The token is exchanged for a
  cookie once — prefetch/replay gets 403. (Legacy `?session=` query
  links still work via the same consent flow.)
- **Everything not listed is untrusted input** — Host headers,
  Origin, cookies, query params, WebSocket payloads, RFB bytes.

## Verifiable claims (replaces absolutes)

The project's security test output is reproducible: `pytest tests`
runs the adversarial/boundary cases for every row above. Dependency
scanning (pip-audit) covers the *declared* Python dependency set at
scan time — it does not cover OS packages, external binaries
(TigerVNC/UltraVNC/ffmpeg/nginx), or unknown vulnerabilities.
