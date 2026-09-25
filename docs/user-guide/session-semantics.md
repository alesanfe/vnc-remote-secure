# Ephemeral session semantics

Exact rules for `single_use`, `max_uses`, expiry, IP binding, and
resource binding — the documented contract the tests enforce.

## Lifecycle

```text
create (CLI)  →  signed token  →  share link /share#t=<token>
                                        │
                                        ▼
                              React SPA (SharePage) reads the
                              fragment and wipes it from the URL
                                        │
                                        ▼
                              POST /api/v1/session/preview
                              (non-consuming grant summary
                               → consent card)
                                        │
                                        ▼
                    on consent: POST /api/v1/session/activate
                              (verify signature + is_valid +
                               atomic consume for single_use)
                                        │
                                        ▼
                              vnc_ephemeral cookie set → /
                                        │
                    every request/upgrade → is_valid() again
                                        │
                              revoked / expired / used → 403
```

Generated links are **fragment URLs** (`/share#t=<token>`): the token
never appears in a request URL, so it cannot land in access logs,
Referer headers, or browser history. The SPA sends it in the JSON
body of two public endpoints — `POST /api/v1/session/preview`
returns a non-consuming grant summary (role, expiry, restrictions)
that backs the consent card, and only explicit consent triggers
`POST /api/v1/session/activate`, which performs the exchange
(`activate_ephemeral_session`) and sets the `vnc_ephemeral` HttpOnly
cookie. The user then lands on `/` (the public portal). There is no
GET-based token exchange.

Legacy `/?session=<token>` links still work for compatibility — the
SPA reads the query parameter, wipes it from the URL, and renders the
same consent flow — but they are never generated anymore.

## single_use

- Consumed **at exchange time** (`activate_ephemeral_session`, invoked
  by `POST /api/v1/session/activate`), not per WebSocket upgrade.
  One token = one cookie issue.
- Consumption is atomic through the shared-state backend — two
  simultaneous exchanges of the same token: exactly one wins.
- After the cookie is set, the session lives until `expires_at`,
  revocation, or logout — reconnects and multiple tabs sharing the
  cookie do NOT consume more uses.
- A failed activation still burns nothing: signature failures and
  `is_valid` failures reject before the consume step.

## max_uses

- `0` (default) = unlimited exchanges until expiry/revocation.
- `N` = at most N successful `is_valid` gates total (exchange +
  per-request validation increments `use_count` via `mark_used`
  only on consume paths; the counter is the boundary enforced in
  `is_valid` — `use_count >= max_uses` → invalid).
- `single_use=True` is equivalent to `max_uses=1` at the exchange
  boundary, plus the `used` flag.

## expires_at

- Absolute wall-clock deadline (`time.time() > expires_at` →
  invalid). Checked on every `is_valid` call — a session that
  expires mid-connection fails the next request/upgrade AND its live
  WebSockets are closed by the revocation watcher (the sweep checks
  expiry alongside the revocation marker).
- There is no sliding renewal for ephemeral sessions.

## IP binding (`allowed_ip`)

- Optional. When set, `client_ip` must match — either an exact IP or
  a CIDR range (`10.0.0.0/24`). A missing client IP fails closed.
- `--allowed-ip first-observed` pins the session to **whoever
  activates the link first** — useful when the client's IP is
  unknowable at creation time (mobile networks, CGNAT). Weaker than
  a fixed binding: the first redeemer becomes the bound client; it
  stops *later* misuse of the same link.
- It is a **supporting control, not an identity**: CGNAT, VPNs,
  mobile networks and shared proxies can break it or let it be
  shared. Do not rely on it as the primary defence.
- Behind a trusted reverse proxy, `client_ip` comes from
  `X-Forwarded-For` only when `TRUSTED_PROXY` is set — otherwise
  the socket peer (the proxy) is used, which an IP-bound token
  cannot match (fail closed by design).

## Resource binding (`resource`)

- A token created for `resource='desktop'` validates only for the
  desktop resource; `check_permission(..., resource='terminal')`
  fails at `is_valid` *and* `has_permission`.
- Enforced when the caller names a resource — action-level checks
  without resource context assert the permission exists.

## Permission granularity

Umbrella permissions expand to fine-grained members; granting a
fine-grained permission does NOT grant the umbrella:

| Umbrella | Members |
|---|---|
| `control` | `keyboard`, `pointer` |
| `clipboard` | `clipboard_write`, `clipboard_read` |

`audio` is a standalone permission (system-audio capture of the
desktop — privacy-sensitive). Roles `support`, `operator` and
`administrator` grant it; `viewer` does not, so a view-only share
link cannot listen to the machine's audio. Sessions created before
this permission existed keep their stored permission set — a link
that needs audio must be re-created under a current role.

`gamepad` is likewise standalone (experimental input injection) —
granted only to `operator`/`administrator`, blocked by `view_only`,
and deliberately NOT part of the `control` umbrella: full desktop
control should not silently enable a privileged driver path.

- `desktop:keyboard` → RFB `KeyEvent`; `desktop:pointer` →
  `PointerEvent` + `SetDesktopSize`; `desktop:clipboard_write` →
  `ClientCutText` (client→server clipboard push);
  `desktop:clipboard_read` → `ServerCutText` (server→client
  clipboard pull). Dropped at the protocol layer by the RFB filter,
  not just hidden in the UI — the filter decodes the full
  server→client stream (SetEncodings is renegotiated to the
  length-decidable subset so FramebufferUpdate rects stay parseable).
- Roles keep umbrella semantics — `support` = view+control+clipboard
  still means full input + both clipboard directions.
- `session create --permissions view,pointer` creates a
  pointer-without-keyboard session (can't type, can click);
  `--permissions view,clipboard_write` allows pushing clipboard
  content out but not receiving the remote side's.
- `view_only` blocks every input/clipboard permission even if a
  caller granted a fine-grained one explicitly.

## Deployment binding (`instance_id`)

- A token minted on another installation (different persisted
  `instance.id`) never validates here — a leaked token from a
  previous deployment or a restored backup cannot cross over.

## Revocation

- `session revoke` writes a shared-state marker AND force-closes
  the session's live WebSockets via the registry. Revocation
  outlives the session's own TTL so a deleted token cannot
  re-authenticate while it would still be valid.
