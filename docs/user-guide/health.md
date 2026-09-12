# Health API Endpoint

## Overview

The health endpoint provides real-time system status information through a
JSON API. Two implementations coexist:

- **Python (Flask)**: `src/vnc_remote_secure/web/routes/health.py` — served
  via the Flask application in `web/application.py`.
- **Python (stdlib)**: `src/vnc_remote_secure/services/health.py` — a
  zero-dependency `http.server` fallback used when Flask is not installed.

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

- **Open access** when `HEALTH_AUTH_TOKEN` is not set (intended for
  localhost binding).
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
    "ttyd": true,
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

## `/health/all` — Combined system + service health

Returns system metrics plus the service status block above.

```json
{
  "system": {
    "hostname": "pi",
    "os": "Linux 6.1.21-v8+",
    "uptime": "2h 30m",
    "cpu": "12%",
    "memory": "1024MB / 4096MB",
    "disk": "N/A"
  },
  "services": {
    "status": "healthy",
    "services_up": 5,
    "services_total": 5,
    "services": {
      "vnc": true,
      "novnc": true,
      "ttyd": true,
      "health": true,
      "landing": true
    }
  }
}
```

System metrics are collected via the platform adapter
(`platform/linux/metrics.py` or `platform/windows/metrics.py`).

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
| `404` | Unknown path (stdlib server only) |

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
