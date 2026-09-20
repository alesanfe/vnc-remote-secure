# ADR 0010: Unified token signing with type separation

## Status
Accepted

## Context
The project uses three kinds of HMAC-SHA256-signed tokens, each with
the same secret but different payload formats and semantics:

1. **Bearer tokens** (`security.authentication.create_session_token`) —
   `username:expiry` — used by the Flask web UI and the auth gateway.
2. **Persistent session cookies** (`security.sessions.create_session_cookie`) —
   `username:created:expires` — used for browser sessions with CSRF.
3. **Ephemeral access tokens** (`security.ephemeral_sessions.create_ephemeral_token`) —
   `session_token:expires_at:single_use` — used for shareable,
   time-limited, permission-scoped access.

Previously each module duplicated the HMAC signing and verification
logic. Because all three used the same secret and the same
`payload.signature` format, a token of one type could be submitted to
a verifier of another type. Although the payload parsing would
typically fail (wrong number of colon-separated fields), this was a
defence-in-depth gap: a valid bearer token could pass signature
verification in the ephemeral verifier if the payload happened to
parse.

## Decision
Introduce a shared signing utility (`security.token_signing`) that:

- Centralises HMAC-SHA256 signing and verification.
- Adds a **type tag** prefix to every token: `<type>:<payload>.<sig>`.
- The type tag is part of the signed material, so it cannot be
  tampered with.
- Each verifier specifies the expected type; tokens of a different
  type are rejected before payload parsing.

Three type tags are defined:
- `TOKEN_TYPE_SESSION` — persistent browser cookies.
- `TOKEN_TYPE_EPHEMERAL` — ephemeral access tokens.
- `TOKEN_TYPE_BEARER` — Flask web session bearer tokens.

## Alternatives considered
1. **Separate secrets per token type.** Rejected — would complicate
   key rotation and configuration; the type tag achieves the same
   isolation without additional secrets.
2. **Keep duplicated signing code.** Rejected — violates DRY and
   makes it easy to introduce subtle inconsistencies.
3. **JWT-based tokens.** Rejected — adds a dependency and
   over-engineers the simple `payload.signature` format.

## Consequences
- All signed tokens now carry a type prefix, changing the token
  format. Existing tokens issued before the change are invalid;
  users must re-authenticate. This is acceptable because all token
  types are short-lived.
- Adding a new token type requires a new `TOKEN_TYPE_*` constant in
  `token_signing.py` so that existing verifiers reject unknown types.
- Cross-type replay is now impossible: a session cookie cannot be
  used as an ephemeral token (or vice versa) because the type tag
  mismatch is detected before signature comparison.

## Risks
- Token format change breaks in-flight tokens during a rolling
  deploy. Mitigated by short token lifetimes.
- If a new token type is added without a corresponding
  `TOKEN_TYPE_*` constant, verification will fail silently.
