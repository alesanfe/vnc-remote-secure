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

The command prints a signed fragment URL (`/share#t=<token>`) pointing
at the portal. Whoever opens it sees a consent card describing the
grant and, on accept, gets a `vnc_ephemeral` cookie that is validated
on every WebSocket upgrade (origin, signature, expiry, revocation, IP,
resource, permission). The token lives in the URL fragment — it is
never sent in a request URL.

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
  client→server for sessions without `desktop:control`/
  `desktop:clipboard_write`, and ServerCutText server→client for
  sessions without `desktop:clipboard_read`
  (see `services/rfb_filter.py`). Direct RFB access to the VNC port
  is a separate channel — keep it loopback-only or use a view-only
  VNC password for hard isolation.

### Fine-grained permissions

`--permissions` accepts umbrella and fine-grained names; umbrellas
expand to their members:

| Umbrella | Members | Effect |
|----------|---------|--------|
| `control` | `keyboard`, `pointer` | RFB input filtering |
| `clipboard` | `clipboard_write`, `clipboard_read` | ClientCutText / ServerCutText forwarding |
| `terminal` | `terminal_view`, `terminal_write` | connect vs execute |
| `admin` | `admin_users`, `admin_config`, `admin_audit` | administrative surface |

A `terminal_view` session opens the terminal and uses read-only
builtins (`help`, `history`, `cls`, `exit`) but every command
execution is refused — the subprocess gate, not the client, enforces
it. `terminal_write` (or the `terminal` umbrella) spawns commands.

Example — a read-only diagnostics link:

```bash
vnc-remote session create --resource terminal --permissions terminal_view
```

`--no-terminal` blocks all three terminal permissions; `--view-only`
blocks the whole terminal surface.

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

## Operator accounts (multi-user RBAC)

Beyond the single env-configured credential, named operator accounts
can be created with scoped roles:

```bash
vnc-remote operator add alice --role operator   # prompts for password
vnc-remote operator add bob --role viewer
vnc-remote operator list
vnc-remote operator role bob admin
vnc-remote operator disable bob
vnc-remote operator remove bob
```

| Operator role | Permissions | Can do |
|---------------|-------------|--------|
| `admin` | `admin:*` → all `admin_*` | everything: manage operators, sessions, config, audit |
| `operator` | `admin_sessions`, `admin_audit` | session list/revoke/revoke-all, gamepad kill-switch, audit view |
| `viewer` | — | read-only portal (no mutations) |

Rules:

- The **store is checked first**; the env `admin`/`LANDING_PASSWORD`
  credential remains the bootstrap admin when no store entry exists
  for the username. A username that IS stored does **not** fall back
  to the env password — stored users authenticate only against their
  own credentials.
- Mutating API endpoints (`POST /api/v1/sessions/revoke`,
  `/sessions/revoke-all`, `/gamepad/stop|resume`) require
  `admin_sessions` — a `viewer` authenticates but gets 403 on
  mutations.
- System-user management (`POST`/`DELETE /api/v1/system-users`)
  requires `admin_users` in addition to step-up auth.
- Passwords are stored as `pbkdf2:sha256` in
  `<data_dir>/operator_users.json` (`0o600`, atomic writes) and are
  prompted via getpass — never accepted as CLI arguments.

## Properties

- Tokens are HMAC-signed with a `ephemeral` type tag — they cannot be
  substituted for session cookies or bearer tokens (see
  `docs/adr/0010-unified-token-signing.md`).
- Sessions are bound to the deployment's persisted instance id — a
  token issued by a different deployment never authenticates here.
- Revocation and single-use claims are atomic across processes through
  the shared-state backend (`SHARED_STATE_BACKEND=sqlite` by default).
