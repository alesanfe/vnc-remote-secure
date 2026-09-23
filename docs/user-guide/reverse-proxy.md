# Reverse proxy guide

How to expose VNC Remote Secure behind a reverse proxy (nginx is the
supported built-in; the same rules apply to any external proxy).

## Architecture

```
Internet ──► nginx (public :443, TLS) ──► loopback backends
                │                            ├─ landing   :8080
                │                            ├─ novnc     :6080
                │                            ├─ websockify:5700  ← never public
                │                            ├─ terminal  :7681
                │                            ├─ health    :8090
                │                            └─ vnc (RFB) :5900  ← never public
```

**Only the proxy port is public.** Every backend binds `127.0.0.1`.
The RFB port and the websockify bridge must *never* listen on a
public interface — RFB authentication is the legacy 8-char DES
scheme, and websockify sits inside the auth-gateway trust boundary.

The service manager enforces this automatically: after every
`start`, the post-start listener audit scans the socket table and
reports any internal port bound publicly (critical for RFB and
websockify; other backends only when `NGINX_ENABLED=true`, since
without a proxy they legitimately *are* the public entry points).
`vnc-remote doctor` and `vnc-remote security check` run the same
check on demand.

## Enabling the built-in proxy

```ini
NGINX_ENABLED=true
TLS_ENABLED=true
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
```

The installer renders `config/nginx.conf` with the loopback
upstreams above and redirects HTTP→HTTPS.

## Forwarded headers (TRUSTED_PROXY)

`X-Forwarded-For` is honored **only** when all of the following
hold:

1. `TRUSTED_PROXY=true`
2. The direct TCP peer is loopback **or** listed in
   `TRUSTED_PROXY_IPS` (comma-separated IPs or CIDR ranges,
   e.g. `TRUSTED_PROXY_IPS=10.0.0.0/24,192.168.1.10`).

A client that can reach a backend port directly can never spoof its
IP via forwarded headers — `TRUSTED_PROXY` does not make them
trusted. Malformed entries in `TRUSTED_PROXY_IPS` fail closed (the
entry is ignored).

Rate limiting, IP-bound sessions, and audit logs all use the IP
resolved through this path — a misconfigured allowlist either hides
the real client (fail-safe: limiter sees the proxy) or, worse,
trusts attacker-supplied headers. Keep `TRUSTED_PROXY_IPS` tight.

### External (off-box) proxy checklist

- TLS terminates at the proxy; backends stay HTTP on loopback.
  Do NOT forward `X-Forwarded-Proto` trust blindly — keep
  `SESSION_COOKIE_SECURE=true` (the default) only when the
  deployment is actually HTTPS at the edge.
- Strip client-supplied `X-Forwarded-*` before adding your own:
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
  overwrites rather than appends in nginx.
- WebSocket upgrade headers are required for `/websockify`,
  `/ws-terminal`, `/ws-audio`, `/ws-gamepad`:
  `proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "upgrade";`
- Increase `proxy_read_timeout` for the desktop stream (sessions
  are long-lived), or the proxy will reap idle-looking VNC traffic.

## Verify after deployment

```bash
vnc-remote doctor           # security.public_listeners check
vnc-remote security check   # aggregated posture + listeners
ss -tlnp | grep -E '5900|5700'   # RFB and websockify must be 127.0.0.1
```

Both commands exit non-zero when an internal service is exposed.
