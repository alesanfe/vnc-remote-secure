# ADR 0012: Delegated SSO and opt-in operator-session IP binding

## Status
Accepted

## Context

Peer remote-access gateways (Guacamole, MeshCentral, Teleport) ship
OIDC/SAML SSO and IP-bound session tokens. Two questions for this
project: should the Python core implement its own SSO, and should
operator cookies be bound to the client IP?

## Decision

### SSO stays at the reverse proxy, not in the product

VNC Remote Secure deliberately ships a **local operator store**
(usernames, TOTP, WebAuthn passkeys, step-up grants) rather than an
embedded OIDC/SAML client:

- The canonical deployment is a single host behind the operator's
  own nginx — fronting it with Authentik/Keycloak/oauth2-proxy adds
  SSO *without* new code paths in the trust boundary
  (`docs/user-guide/reverse-proxy.md`). Guacamole itself runs OIDC
  as an optional extension layered on top of local auth, not a
  replacement for it.
- An embedded OIDC client is a permanent attack surface (redirect
  validation, state/nonce handling, claim mapping) in exchange for a
  feature most self-hosted single-operator deployments never use.
- The auth-policy engine (`security/auth_policy.py`) and audit trail
  already model "who authenticated, how, and when" — an external IdP
  can be integrated later through the gateway layer without
  redesigning authorization.

### Operator-session IP binding exists but is opt-in

`OP_SESSION_IP_BIND=true` folds the issuing client IP into the
`vnc_op` cookie HMAC — a stolen cookie then fails verification from
any other address. This matches MeshCentral's token binding and
protects the highest-value credential in the system.

It is **not** the default because it punishes legitimate roaming:
a laptop switching Wi-Fi ↔ mobile data or crossing a CGNAT boundary
changes source IP mid-session and would be logged out. Operators on
static networks (typical for this product's admin console) can enable
it; mobile-heavy operators should not.

## Consequences

- Operators wanting enterprise SSO deploy an IdP in front of the
  portal; the local store remains the break-glass path.
- `vnc_op` cookies minted with binding OFF stop verifying the moment
  the flag flips ON (signature shape changes) — an explicit, safe
  migration path.
- Out of scope remains: embedded OIDC/SAML, Kerberos, LDAP.
