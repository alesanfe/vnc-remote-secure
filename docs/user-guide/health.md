# Health API Endpoint

## Overview

The health endpoint provides real-time system status information through a
JSON API. A single FastAPI application
(`src/vnc_remote_secure/backend/health_app.py`, served by uvicorn) backs
both service processes:

- **Health service**: `src/vnc_remote_secure/services/health.py` on
  `HEALTH_WEB_PORT`.
- **Internal health/metrics service (`user_ui`)**:
  `src/vnc_remote_secure/web/application.py` on `USER_UI_PORT` — despite
  the historical name it exposes no UI pages; every browser-facing page
  is the React SPA served by the portal.

Both expose the same contract documented below.

## Endpoint Details

### URL

```
GET http://<host>:<HEALTH_WEB_PORT>/health
GET http://<host>:<HEALTH_WEB_PORT>/health/all
```

- `HEALTH_WEB_PORT` defaults to `8080` on Linux and `8090` on Windows.
- `HEALTH_WEB_HOST` defaults to `127.0.0.1` (localhost only). Set it to
  `0.0.0.0` to expose the endpoint on the LAN (use with `HEALTH_AUTH_TOKEN`).

### Authentication

- **Open access** when `HEALTH_AUTH_TOKEN` is not set — **only** while
  every health-serving bind is loopback (`HEALTH_WEB_HOST`,
  `USER_UI_HOST` and `BIND_HOST` all resolve to localhost). If any of
  them is public and no token is set, requests fail closed with `401`.
- **Bearer token** required when `HEALTH_AUTH_TOKEN` is set. Send the
  `Authorization: Bearer <token>` header.
- On failure, the server returns `401` with
  `WWW-Authenticate: Bearer realm="Health"`.

### Response Format

- **Content-Type**: `application/json`
- **Body**: JSON object (see schemas below)

## `/health` — Service health

Returns aggregated service status.

```json
{
  "status": "healthy",
  "services_up": 5,
  "services_total": 5,
  "services": {
    "vnc": true,
    "novnc": true,
    "terminal": true,
    "health": true,
    "landing": true
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `healthy` (all up), `degraded` (some up), `down` (none up), or `unknown` |
| `services_up` | int | Number of services listening |
| `services_total` | int | Total number of tracked services |
| `services` | object | Map of service name to listening boolean |

Aliases: `/health_status` and `/health_status.json` return the same payload.

## `/health/live` — Liveness probe

Returns a minimal liveness check (always `200` when the process is running).

```json
{
  "status": "alive"
}
```

## `/health/ready` — Readiness probe

Returns service readiness. Returns `200` with `{"status": "ready"}`
when all enabled services are listening, or `503` with
`{"status": "not ready"}` otherwise.

## `/health/services` — Per-service status

Returns detailed per-service status including PID and port information.

```json
{
  "vnc": {"running": true, "pid": 12345, "port": 5901},
  "terminal": {"running": true, "pid": 12346, "port": 5000}
}
```

## `/health/all` — Combined system + service health

Returns system metrics plus the service status block above. Metric
format is platform-specific (Linux reports load averages and percentages;
Windows reports CPU percentage and raw byte counts).

```json
{
  "system": {
    "hostname": "pi",
    "os": "Linux 6.1.21-v8+",
    "uptime": "2h 30m",
    "cpu": "Load: 0.12",
    "memory": "25% (1024 MB / 4096 MB)",
    "disk": "/ 10G (5G used)"
  },
  "services": {
    "status": "healthy",
    "services_up": 5,
    "services_total": 5,
    "services": {
      "vnc": true,
      "novnc": true,
      "terminal": true,
      "health": true,
      "landing": true
    }
  },
  "posture": {
    "score": 78,
    "checks": [],
    "summary": "Good security posture with minor gaps",
    "deployment_decision": "allowed",
    "blocking_findings": []
  }
}
```

The `posture` key carries the security-posture report (score and
findings) documented in the monitoring runbook; it is best-effort and
may be `{}` if posture calculation fails.

> **Note:** `/health` returns HTTP `503` when the aggregate status is
> `down` or `unknown` — identical behaviour on the standalone health
> server and the `user_ui` service (same FastAPI app).

System metrics are collected via the platform adapter
(`src/vnc_remote_secure/platform/linux/metrics.py` or `src/vnc_remote_secure/platform/windows/metrics.py`).

## Error Responses

All errors use the unified JSON envelope:

```json
{
  "error": true,
  "message": "Unauthorized"
}
```

| Status | Cause |
|--------|-------|
| `401` | Missing or invalid `HEALTH_AUTH_TOKEN` |
| `404` | Unknown path |

## Integration Examples

### Simple health check

```bash
curl -s http://127.0.0.1:8080/health | jq '.status'
```

### With Bearer token

```bash
curl -s -H "Authorization: Bearer $HEALTH_AUTH_TOKEN" \
  http://127.0.0.1:8080/health/all | jq '.system.cpu'
```

### Monitoring script

```bash
#!/bin/bash
HEALTH_URL="http://127.0.0.1:8080/health"
RESPONSE=$(curl -s -f "$HEALTH_URL") || exit 1
STATUS=$(echo "$RESPONSE" | jq -r '.status')
if [ "$STATUS" = "healthy" ]; then
  echo "System healthy"
  exit 0
else
  echo "System issues detected: $STATUS"
  exit 1
fi
```

## Troubleshooting

### Health endpoint not responding

```bash
# Check the port
ss -tlnp 2>/dev/null | grep :8080 || netstat -ano | grep :8080

# Restart the stack
vnc-remote restart
```

### 401 Unauthorized

```bash
# Verify the token is set and matches
grep HEALTH_AUTH_TOKEN .env
curl -H "Authorization: Bearer $(grep HEALTH_AUTH_TOKEN .env | cut -d= -f2)" \
  http://127.0.0.1:8080/health
```

## Security Considerations

- **Bind to localhost by default**: `HEALTH_WEB_HOST=127.0.0.1`.
- **Set `HEALTH_AUTH_TOKEN`** when binding to `0.0.0.0`.
- **No sensitive data**: Only status booleans and system metrics are exposed.
- **Access logs**: routed to the application logger at INFO level.
