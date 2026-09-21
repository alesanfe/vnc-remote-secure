# Temporary shared sessions

`vnc-remote session` creates signed, time-limited share links that grant
browser access without giving away the operator credentials. Sessions
live in the runtime directory and are enforced consistently across every
service (desktop, terminal, audio, gamepad).

## Create a share link

```bash
vnc-remote session create                      # viewer, 30 minutes
vnc-remote session create --expires 2h --role support
vnc-remote session create --single-use         # link dies on first use
vnc-remote session create --max-uses 3         # up to 3 activations
vnc-remote session create --resource desktop   # desktop only, no terminal
vnc-remote session create --allowed-ip 192.0.2.10
vnc-remote session create --view-only          # no control channels
vnc-remote session create --no-terminal        # block terminal
vnc-remote session create --json               # machine-readable output
```

The command prints a signed URL pointing at the landing portal. Whoever
opens it gets a `vnc_ephemeral` cookie that is validated on every
WebSocket upgrade (origin, signature, expiry, revocation, IP, resource,
permission).

### Roles

| Role | Permissions |
|------|-------------|
| `viewer` | view |
| `support` | view, control, clipboard |
| `operator` | view, control, clipboard, file_transfer, terminal |
| `administrator` | all |

### Binding options

- `--resource {desktop,terminal,audio,gamepad}` — the token only opens
  the named resource; a `desktop` token cannot open a terminal.
- `--allowed-ip` — fail-closed IP restriction.
- `--single-use` / `--max-uses` — atomic, cross-process use counters.
- `--view-only` — blocks control channels (gamepad, terminal, file
  transfer) **and** filters RFB input at the protocol layer: the
  noVNC WebSocket relay drops KeyEvent/PointerEvent/ClientCutText
  messages for sessions without `desktop:control`/`desktop:clipboard`
  (see `services/rfb_filter.py`). Direct RFB access to the VNC port
  is a separate channel — keep it loopback-only or use a view-only
  VNC password for hard isolation.

## List and revoke

```bash
vnc-remote session list
vnc-remote session revoke <token-or-id>
```

`session list` prints a public `id=` fingerprint for each active
session. `revoke` accepts the full token, the raw `vnc_ephemeral`
cookie value, or that `id` — so a session can be revoked even when
the original link is lost.

Revoking a session is immediate: the shared-state revocation is
propagated to all service processes and every live WebSocket connection
registered for that session is force-closed.

## Properties

- Tokens are HMAC-signed with a `ephemeral` type tag — they cannot be
  substituted for session cookies or bearer tokens (see
  `docs/adr/0010-unified-token-signing.md`).
- Sessions are bound to the deployment's persisted instance id — a
  token issued by a different deployment never authenticates here.
- Revocation and single-use claims are atomic across processes through
  the shared-state backend (`SHARED_STATE_BACKEND=sqlite` by default).
