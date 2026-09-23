# Privacy and data retention

What VNC Remote Secure stores, where, and how to purge it. The
product is self-hosted — all data stays on the machine unless you
configure outbound channels (alerts, DuckDNS, Let's Encrypt).

## What is stored

| Data | Location | Contains | Retention |
|---|---|---|---|
| Configuration | `.env`, system `config.env` | Ports, flags, **secrets** (passwords, tokens) | Until deleted |
| SSL material | `<ssl_dir>` | Private keys, certificates | Until rotated/deleted |
| Audit log | `AUDIT_LOG_FILE` | Events: auth attempts, session lifecycle, revocations, service lifecycle, **usernames + source IPs** | Rotated at `AUDIT_LOG_MAX_BYTES` (default 10 MB) |
| Shared-state DB | `<run_dir>/shared_state.db` | Rate-limit counters, revocations, TOTP claims, used recovery codes, metric counters | TTL per record; cleaned by `SessionStore.cleanup` / backend expiry |
| Ephemeral sessions | `<run_dir>/ephemeral_sessions.json` | Session metadata: role, permissions, expiry, IP binding, `created_by` | Until expiry + cleanup |
| Signing secret | `<run_dir>/auth_secret.key` + retired-keys file | Token/cookie signing keys | Previous keys kept for the rotation coexistence window (default 7 days), verify-only, then retired |
| Generated credentials | `<run_dir>/generated_credentials.env` | Auto-generated passwords | Until overwritten/removed |
| Backups | `<backup_dir>` | Everything above (encrypted when `BACKUP_PASSWORD` set) | Manual |
| PID/state files | `<run_dir>/pids/` | Service PIDs | Rewritten each start |

## What is NOT stored

- Raw share-link tokens in logs, metrics, or session listings —
  only sha256 fingerprints (`token_id`).
- Command contents typed into the web terminal (audit records
  open/close + duration, never the commands).
- Clipboard contents, keystrokes, audio data — relayed in memory,
  not persisted.
- Full tokens or passwords in Prometheus metrics (labels are
  fixed-value only).

## Retention and purge

```bash
# Expire + clean sessions and shared-state records
vnc-remote session revoke --all        # kill every active link
# Audit log rotation is automatic; purge history manually:
rm "$AUDIT_LOG_FILE"                    # or truncate — chain resets
# Remove generated credentials (they regenerate on next start):
rm <run_dir>/generated_credentials.env
# Full removal (keeps backups/config unless --purge):
vnc-remote uninstall
```

## Outbound data

- **DuckDNS**: your public IP is sent to duckdns.org on each update.
- **Alerts** (Discord/webhook/email): title, severity, message and
  a correlation id — the dispatcher redacts URLs and never sends
  secrets; message contents come from internal callers.
- **Let's Encrypt**: domain + contact email to the CA when used.

## Audit log caveat

The hash chain is **tamper-evident, not immutable** — an attacker
with host control can rewrite it. `AUDIT_MIRROR_FILE` mirrors each
entry to a second path (a mounted share or WORM store) so rewriting
the primary log leaves the mirror intact; remote syslog/webhook
export is the stronger option for high-assurance deployments.
