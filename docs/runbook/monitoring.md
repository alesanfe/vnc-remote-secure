# Monitoring Runbook

Operational guide for monitoring and troubleshooting VNC Remote Secure.

## Health endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `/health/live` | No | Liveness probe (process alive) |
| `/health/ready` | Yes | Readiness probe (all services ready) |
| `/health` | Yes | Overall health status |
| `/health/services` | Yes | Per-service health |
| `/health/all` | Yes | Complete report (system + services + posture) |

> `/metrics`, `/audit` and `/audit/verify` are served by **both** the
> standalone health server (on `HEALTH_WEB_PORT`) and the Flask
> user-management UI (on `USER_UI_PORT`, default `8081`) — the two
> implementations are kept at parity.

> The standalone health server is optional: `HEALTH_WEB_ENABLED=false`
> disables it, in which case the Flask UI is the only source of these
> endpoints (point Prometheus at `USER_UI_PORT` instead). A disabled
> health server is also excluded from `/health` port probing and the
> `vnc-remote status`/`doctor` checks.

### Default ports

| Platform | Health port | User UI port (metrics/audit) |
|----------|------------|------------------------------|
| Linux | 8080 | 8081 |
| Windows | 8090 | 8081 |

## Prometheus metrics

### Scrape config

```yaml
scrape_configs:
  - job_name: 'vnc-remote-secure'
    static_configs:
      # Health server /metrics — 8080 on Linux, 8090 on Windows.
      - targets: ['127.0.0.1:8080']
    metrics_path: '/metrics'
    # When HEALTH_AUTH_TOKEN is configured, pass it as a bearer token:
    # authorization:
    #   credentials: '<HEALTH_AUTH_TOKEN>'
```

### Available metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vnc_remote_up` | gauge | Service status (1=up, 0=down) |
| `vnc_remote_session_active` | gauge | Active ephemeral sessions |
| `vnc_remote_auth_attempts_total` | counter | Login attempts (by result) |
| `vnc_remote_tls_enabled` | gauge | TLS status (1=enabled, 0=disabled) |
| `vnc_remote_posture_score` | gauge | Security posture score (0-100) |
| `vnc_remote_health_check_total` | counter | Health check results |
| `vnc_remote_process_start_time` | gauge | Process start time (Unix epoch) |

### Grafana dashboard queries

```
# Service status over time
vnc_remote_up

# Active sessions
vnc_remote_session_active

# Auth failure rate
rate(vnc_remote_auth_attempts_total{result="failure"}[5m])
 / rate(vnc_remote_auth_attempts_total[5m])

# Posture score trend
vnc_remote_posture_score

# TLS status
vnc_remote_tls_enabled
```

## Audit log

The audit log is at `logs/audit.jsonl` (configurable via `AUDIT_LOG_FILE`).
Each line is a JSON entry with a tamper-evident SHA-256 chain hash.

### Verify chain integrity

```bash
python -c "
import sys; sys.path.insert(0, 'src')
from vnc_remote_secure.security.audit import verify_chain
print(verify_chain())
"
```

### Query recent entries

```bash
python -c "
import sys; sys.path.insert(0, 'src')
from vnc_remote_secure.security.audit import get_audit_entries
for e in get_audit_entries(limit=20, event='login'):
    print(e)
"
```

## Troubleshooting

### Service won't start

1. Run `vnc-remote doctor` to check readiness.
2. Check logs: `vnc-remote status` shows log paths.
3. Verify `.env` has no default or example passwords.
4. Check port conflicts: `netstat -tlnp | grep -E '8000|8080|6080|5901'`.

### Authentication fails

1. Check `AUTH_SECRET` is set in `.env`.
2. Check `FLASK_SECRET_KEY` is set.
3. If MFA is enabled, verify `TOTP_SECRET` is valid.
4. Check rate limiting: `AUTH_MAX_ATTEMPTS` and `AUTH_LOCKOUT_SECONDS`.
5. Check audit log for failed attempts: see above.

### TLS certificate issues

1. Run TLS validation:
   ```bash
   python -c "
   import sys; sys.path.insert(0, 'src')
   from vnc_remote_secure.security.tls_validation import validate_tls_config
   for f in validate_tls_config():
       print(f'{f[\"severity\"]}: {f[\"message\"]}')
   "
   ```
2. Verify `SSL_CERT` and `SSL_KEY` paths exist.
3. Check certificate expiry (validation reports it).
4. For Let's Encrypt: `certbot renew --dry-run`.

### Posture score is low

1. Get the full posture report:
   ```bash
   python -c "
   import sys; sys.path.insert(0, 'src')
   from vnc_remote_secure.security.posture import calculate_posture
   import json; print(json.dumps(calculate_posture(), indent=2))
   "
   ```
2. Address critical findings first (they block deployment).
3. Common issues:
   - Backend bound to 0.0.0.0 → set `BIND_HOST=127.0.0.1`
   - TLS disabled in public profile → set `TLS_ENABLED=true`
   - MFA disabled in public profile → set `MFA_REQUIRED=true`
   - No nginx in public profile → set `NGINX_ENABLED=true`

### Secret file permissions

1. Validate permissions:
   ```bash
   python -c "
   import sys; sys.path.insert(0, 'src')
   from vnc_remote_secure.security.file_permissions import validate_secret_files
   for f in validate_secret_files():
       print(f'{f[\"severity\"]}: {f[\"message\"]}')
   "
   ```
2. Fix permissions:
   ```bash
   # Linux (canonical dirs; legacy project-local data/ssl/ssl/secrets
   # are also checked by validate_secret_files when present)
   chmod 600 .env *.pem *.key
   chmod 700 /var/lib/vnc-remote-secure/ssl

   # Windows (PowerShell)
   icacls .env /inheritance:r /grant:r "$env:USERNAME:F"
   ```

### WebSocket connection fails

1. Check `ALLOWED_ORIGINS` includes your origin.
2. Verify nginx is proxying WebSocket upgrades.
3. Check the auth gateway is not blocking the upgrade.
4. Check audit log for `ws_upgrade` events.

## Alerts

### Built-in alert dispatch

The Python service manager dispatches alerts directly when
`ALERTS_ENABLED=true` and at least one channel is configured:
`DISCORD_ENABLED`+`DISCORD_WEBHOOK_URL`, `ALERT_WEBHOOK_URL`, or the
`ALERT_EMAIL_*`/`ALERT_SMTP_*` settings. Alerts fire on service start
failures and watchdog transitions (services going down or being
restarted), never on a per-request basis.

The watchdog runs inside `vnc-remote service --run` and
`vnc-remote start --foreground`: every `HEALTHCHECK_INTERVAL`
seconds it checks all enabled services; when `AUTO_RESTART=true`
dead services are restarted in place.

### Certificate expiry

The TLS validation reports warnings when a certificate expires in <30 days.
Set up a cron job:

```bash
# Daily cert check
0 8 * * * cd /path/to/vnc-remote-secure && python -c "
import sys; sys.path.insert(0, 'src')
from vnc_remote_secure.security.tls_validation import validate_tls_config
for f in validate_tls_config():
    if f['severity'] in ('critical', 'warning'):
        print(f)
"
```

### Service down

Use the `/health/live` endpoint with your monitoring system:

```bash
# Cron job
*/5 * * * * curl -sf http://127.0.0.1:8080/health/live || \
    echo "VNC Remote Secure is down" | mail -s "Alert" your-email@your-domain.duckdns.org
```

### Posture degradation

Monitor the posture score via Prometheus:

```
ALERT VncPostureLow
  IF vnc_remote_posture_score < 70
  FOR 5m
  LABELS { severity = "warning" }
  ANNOTATIONS {
    summary = "VNC Remote Secure posture score is low",
    description = "Posture score is {{ $value }}, below 70."
  }
```

## Backup and recovery

### Backup

```bash
vnc-remote backup
```

Creates a tarball with:
- `.env` (project env file, with secrets)
- `system-config.env` (the platform config seeded by the installer:
  `/etc/vnc-remote-secure/config.env` or, on Windows,
  `%ProgramData%\VncRemoteSecure\config.env` when elevated /
  `%LOCALAPPDATA%\VncRemoteSecure\config.env` otherwise —
  `AppData\LocalLow` under Store/MSIX-packaged Python)
- `ssl/` (the platform SSL directory: `/var/lib/vnc-remote-secure/ssl`,
  `~/.local/share/vnc-remote-secure/ssl`, or
  `%ProgramData%\VncRemoteSecure\ssl`)
- `config/` (the platform config directory)
- `data/` (the platform data directory; `*.log` files are excluded)
- `run/auth_secret.key`, `run/generated_credentials.env`,
  `run/ephemeral_sessions.json`, `run/instance.id` and
  `run/shared_state.db` — the signing secret, generated credentials,
  share sessions, deployment identity and durable shared state.
  Without them a restore silently regenerates credentials and un-burns
  consumed recovery codes / TOTP timesteps (replay).
- `service_state.json` (service-manager PID state)

When `BACKUP_PASSWORD` is set the archive is Fernet-encrypted and uses
the `.enc.tar.gz` extension.

### Restore

```bash
vnc-remote restore
```

Restores from the most recent backup. Pass a backup file path
positionally to restore a specific archive:

```bash
vnc-remote restore backups/vncrs-backup-YYYYMMDD-HHMMSS.tar.gz
vnc-remote backup --list   # list available backups
```
