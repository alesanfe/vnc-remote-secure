# Feature & Toggle Registry

The project's "flags" are environment/config toggles rather than a
flag service — same discipline applies: every toggle must have an
owner, a default, a reason and a lifecycle note. Kill-switches are
marked; a toggle without a reason to exist becomes debt.

| Toggle | Default | Effect | Owner | Lifecycle |
|--------|---------|--------|-------|-----------|
| `OP_SESSION_IP_BIND` | off | Bind `vnc_op` cookie HMAC to client IP | security | stable, opt-in (ADR-0012) |
| `SESSION_COOKIE_SECURE` | on | Secure flag on session cookies | security | stable; only off for LAN-dev |
| `SESSION_IDLE_TIMEOUT` / `SESSION_MAX_LIFETIME` | 30 min / 8 h | session lifetimes | security | stable |
| `KEEP_TEMP_USER` | off | keep the temporary Linux user | platform | stable; do not flip without reason (AGENTS.md) |
| `SHARED_STATE_BACKEND` | sqlite | memory vs sqlite backend | core | stable (ADR-0011) |
| `SHARED_STATE_STRICT` | — | fail closed on shared-state errors | core | stable |
| `HEALTH_AUTH_TOKEN` / `METRICS_AUTH_TOKEN` / `AUDIT_AUTH_TOKEN` | unset→loopback-open | scoped Bearer on health surface | security | stable |
| `MAINTENANCE` (`maintenance on/off`) | off | drain mode | ops | runtime kill-switch |
| `TERMINAL_ENABLED` / `AUDIO_ENABLED` / `GAMEPAD_ENABLED` | per profile | service toggles | product | stable |
| `OTEL_ENABLED` | off | OTLP trace export (extra dep) | observability | experimental |
| `VRS_TEST_MODE` | off in prod | test isolation guard (`core/test_isolation.py`) | dev | test-only |
| `SECURITY_PROFILE` | default | strict/hardened profile presets | security | stable |
| `RECORDING_ENABLED` | per profile | session recording | product | stable |
| `VNC_WEBAUTH`/`LANDING_*` auth toggles | per profile | portal auth shape | security | stable |

## Rules for a new flag

- Document it here **and** in `config.schema.json` + `.env.example`.
- Default must be the safe choice; a flag whose default is the
  insecure posture is a bug.
- Kill-switches get a "who can flip it" note; rollout flags get an
  expiry date.
