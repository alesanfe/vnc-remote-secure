# Production hardening checklist

What to verify before exposing a deployment beyond localhost.
`vnc-remote security check` automates most of this — run it last.

## Profile and entry point

- [ ] `SECURITY_PROFILE=public-hardened` (or `private-overlay` for
      tunnel-only deployments). These profiles fail closed on
      missing TLS/MFA/proxy prerequisites instead of warning.
- [ ] `NGINX_ENABLED=true` — exactly one public listener. All
      backends bind loopback; RFB (5900+) and websockify (5700)
      are **never** public. Verified automatically by the
      post-start listener audit and `doctor`.
- [ ] `TLS_ENABLED=true` with a real certificate (Let's Encrypt via
      `DUCK_DOMAIN`+`EMAIL`, or your own PEM pair). Self-signed is
      acceptable for lab only.

## Authentication

- [ ] Strong `USER_UI_PASSWORD` / `TTYD_PASSWD` (never defaults —
      `validate_password` rejects known-weak values anyway).
- [ ] `MFA_REQUIRED=true` for operator access.
- [ ] `VNC_PASSWORD` unset or auto-generated — it is a legacy
      8-char DES credential, a *secondary* internal defence, never
      the perimeter. The perimeter is the authenticated gateway.
- [ ] `TRUSTED_PROXY=false` unless an off-box proxy exists; when
      true, pin `TRUSTED_PROXY_IPS` to the proxy's exact IP/CIDR.

## Optional attack surface

- [ ] Terminal (`TTYD_*`) disabled unless needed — it is remote
      code execution. When enabled: step-up auth is enforced,
      `TERMINAL_IDLE_TIMEOUT` and `TERMINAL_MSG_RATE` apply.
- [ ] `AUDIO_STREAM_ENABLED=false`, `GAMEPAD_ENABLED=false`
      (experimental; keep off in production).
- [ ] Clipboard/file-transfer permissions only in sessions that
      need them — prefer `view_only` or `view`+`pointer` roles for
      read-mostly sharing.

## Operational

- [ ] `BACKUP_PASSWORD` set — backups contain `.env` and SSL keys;
      without it they are plaintext archives of secrets.
- [ ] `AUDIT_LOG_MAX_BYTES` sized for your retention needs; audit
      chain is verified on startup (tamper-evident, local — not
      immutable; see `docs/architecture/trust-boundaries.md`).
- [ ] `ALERTS_ENABLED=true` + at least one channel configured and
      `ALERT_WEBHOOK_SECRET` set for webhook signature.
- [ ] Rate limits left at defaults unless you have measured a need.
- [ ] `.env` file permissions owner-only; never committed to git.
- [ ] Shared-state DB on a local filesystem — **not** NFS, SMB, or
      a synced folder (locking semantics are unreliable there and
      the DB carries security state: revocations, TOTP claims,
      rate limits).

## Verification

```bash
vnc-remote config validate     # contradictions, weak values
vnc-remote doctor              # readiness incl. public listeners
vnc-remote security check      # aggregated posture; exit 1 on critical
vnc-remote verify              # end-to-end health verification
```

All four must pass with no critical findings. `security check`
exit code is suitable for CI/CD gates.
