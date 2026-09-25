"""``session`` command: manage ephemeral remote sessions."""
import hashlib
import json
import os

from vnc_remote_secure.cli._common import _audit_cli


def _parse_duration(s: str) -> int:
    """Parse a duration string like '30m', '2h', '1d' into seconds.

    Rejects negative/zero values and unknown unit suffixes instead of
    silently defaulting, so misconfigured expiries surface immediately.
    """
    from vnc_remote_secure.core.constants import DEFAULT_SESSION_IDLE_TIMEOUT
    if not s:
        return DEFAULT_SESSION_IDLE_TIMEOUT
    s = s.strip().lower()
    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    if s and s[-1] in units:
        try:
            value = int(s[:-1])
        except ValueError as exc:
            raise SystemExit(
                f"Invalid duration: {s!r} (expected e.g. 30m, 2h)") from exc
        if value <= 0:
            raise SystemExit(f"Duration must be positive: {s!r}")
        return value * units[s[-1]]
    try:
        value = int(s)
    except ValueError as exc:
        raise SystemExit(
            f"Invalid duration: {s!r} (expected e.g. 30m, 2h)") from exc
    if value <= 0:
        raise SystemExit(f"Duration must be positive: {s!r}")
    return value


def _share_base_url() -> str:
    """Derive the public base URL for a share link — delegates to
    ``core.share_url``; the alias keeps this module's tests and
    imports working."""
    from vnc_remote_secure.core.share_url import share_base_url
    return share_base_url()


def _validate_allowed_ip(allowed_ip) -> int:
    """Return 1 and print an error when ``--allowed-ip`` is malformed."""
    if not allowed_ip or allowed_ip == 'first-observed':
        return 0
    # Fail fast on a malformed IP — the store validates by
    # string match, so a typo would create a session that
    # never activates.
    import ipaddress
    try:
        raw = allowed_ip.strip()
        if '/' in raw:
            ipaddress.ip_network(raw, strict=False)
        else:
            ipaddress.ip_address(raw)
    except ValueError:
        print(f"Error: --allowed-ip is not a valid IP, CIDR, or "
              f"'first-observed': {allowed_ip!r}")
        return 1
    return 0


def _parse_permissions(raw):
    """Parse ``--permissions a,b,c``; returns (set, error_code)."""
    if not raw:
        return None, 0
    from vnc_remote_secure.security.ephemeral_sessions import ALL_PERMISSIONS
    permissions = {p.strip() for p in raw.split(',') if p.strip()}
    unknown = permissions - ALL_PERMISSIONS
    if unknown:
        print(f"Error: unknown permissions: "
              f"{', '.join(sorted(unknown))}. Valid: "
              f"{', '.join(sorted(ALL_PERMISSIONS))}")
        return None, 1
    if not permissions:
        print("Error: --permissions must name at least one "
              "permission")
        return None, 1
    return permissions, 0


def _print_session_created(args, signed_token, expires_in, role,
                           base_url):
    """Emit the create output in JSON or human-readable form."""
    # Fragment-carried link: the token stays out of the URL path, so it
    # cannot leak via browser history, Referer headers, or server logs.
    share_url = f"{base_url}/share#t={signed_token}"
    if args.json:
        print(json.dumps({
            'token': signed_token,
            'url': share_url,
            'expires_in': expires_in,
            'role': role,
            'view_only': args.view_only,
            'no_terminal': args.no_terminal,
            'single_use': args.single_use,
            'resource': args.resource,
            'max_uses': args.max_uses,
        }, indent=2))
        return
    print(f"Session created (role: {role}, expires in {expires_in}s)")
    print(f"URL: {share_url}")
    if args.view_only:
        print("  View-only: yes")
        print("  NOTE: view-only blocks control channels (gamepad,"
              " terminal, clipboard) and drops RFB input messages"
              " (KeyEvent/PointerEvent/ClientCutText) in the WebSocket"
              " relay. Direct access to the VNC port bypasses this —"
              " keep it loopback-bound.")
    if args.no_terminal:
        print("  Web Terminal: disabled")
    if args.single_use:
        print("  Single-use: yes")
    if args.allowed_ip:
        print(f"  IP restriction: {args.allowed_ip}")
    if args.resource:
        print(f"  Resource: {args.resource} only")
    if args.max_uses:
        print(f"  Max uses: {args.max_uses}")


def _session_create(store, args):
    """Create an ephemeral session and print the share link."""
    from vnc_remote_secure.security.ephemeral_sessions import ROLES
    expires_in = _parse_duration(args.expires or '30m')
    role = args.role or 'viewer'
    if role not in ROLES:
        print(f"Error: unknown role '{role}'. Available: {', '.join(ROLES.keys())}")
        return 1
    if args.max_uses < 0:
        print("Error: --max-uses must be >= 0 (0 = unlimited)")
        return 1
    if _validate_allowed_ip(args.allowed_ip):
        return 1

    permissions, err = _parse_permissions(
        getattr(args, 'permissions', None))
    if err:
        return 1

    # The CLI operator holds a local shell — equivalent to admin:* —
    # so delegation checks pass, but the rules still run through the
    # shared use case (same audit trail, same invariants as the API).
    from vnc_remote_secure.engine.application.sessions import create_share_link
    from vnc_remote_secure.engine.domain.decision import UseCaseError
    actor = ('cli:'
             + (os.environ.get('USERNAME') or os.environ.get('USER')
                or 'admin'))
    try:
        _session, signed_token = create_share_link(
            actor, {'admin:*'},
            role=role, permissions=permissions, ttl=expires_in,
            single_use=args.single_use, view_only=args.view_only,
            no_terminal=args.no_terminal, allowed_ip=args.allowed_ip,
            resource=args.resource, max_uses=args.max_uses)
    except (UseCaseError, ValueError) as e:
        # e.g. EPHEMERAL_REQUIRE_RESOURCE rejects unbound tokens.
        print(f"Error: {e}")
        return 1

    _print_session_created(
        args, signed_token, expires_in, role, _share_base_url())
    # Audited inside SessionStore.create() — a second audit here
    # would emit a duplicate event per session.
    return 0


def _session_list(store, args):
    """List active ephemeral sessions via the shared use case."""
    del store  # the use case resolves the store itself
    from vnc_remote_secure.engine.application.sessions import list_share_links
    sessions = list_share_links('active')
    if args.json:
        print(json.dumps(sessions, indent=2))
    else:
        if not sessions:
            print("No active sessions.")
        else:
            print(f"Active sessions ({len(sessions)}):")
            import time
            for s in sessions:
                remaining = int(s['expires_at'] - time.time())
                perms = ','.join(s.get('permissions') or []) or '-'
                print(f"  id={s.get('token_id', '?')} role={s['role']} "
                      f"expires_in={max(remaining, 0)}s "
                      f"view_only={s['view_only']} single_use={s['single_use']} "
                      f"resource={s.get('resource') or '*'} "
                      f"uses={s.get('use_count', 0)}/{s.get('max_uses', 0) or 'inf'} "
                      f"ip={s.get('allowed_ip') or '*'} "
                      f"perms={perms}")
    return 0


def _session_revoke(args, store=None):
    """Revoke an ephemeral session by token, or all with ``--all``."""
    # Emergency kill-switch: revoke every active session at once —
    # closes live WebSockets via the registry just like a single
    # revoke, so a compromised deployment can be locked down in one
    # command instead of one token at a time.
    # All revocations go through the shared use cases — the API and
    # the CLI must enforce the same semantics (shared-state mark,
    # live-WebSocket close, audit trail).
    from vnc_remote_secure.engine.application.sessions import (
        revoke_all_share_links,
        revoke_share_link,
        revoke_share_links_by,
    )
    actor = ('cli:'
             + (os.environ.get('USERNAME') or os.environ.get('USER')
                or 'admin'))
    if getattr(args, 'all', False):
        revoked = revoke_all_share_links(actor)
        _audit_cli('ephemeral_session_revoke_all', 'success',
                   f'count={revoked}')
        print(f"Revoked {revoked} session(s).")
        return 0
    # Revoke every session created by a given operator — the "kill all
    # sessions for user X" operation (credential change, offboarding,
    # compromised admin account).
    by_user = getattr(args, 'by_user', None)
    if by_user:
        revoked = revoke_share_links_by(actor, by_user)
        _audit_cli('ephemeral_session_revoke_user', 'success',
                   f'user={by_user} count={revoked}')
        print(f"Revoked {revoked} session(s) created by {by_user}.")
        return 0
    # Accept the token either positionally (natural form:
    # ``vnc-remote session revoke <token>``) or via --token.
    token = getattr(args, 'token', None) or getattr(args, 'token_pos', None)
    if not token:
        print("Error: token required for revoke")
        return 1
    # revoke_share_link() (not bare store.revoke) also marks the
    # shared-state revocation and force-closes live WebSocket
    # connections registered for this session.
    ok = revoke_share_link(actor, token)
    # Token is a credential — audit only its fingerprint.
    _audit_cli('ephemeral_session_revoke',
               'success' if ok else 'failure',
               f'token_sha256={hashlib.sha256(token.encode()).hexdigest()[:12]}')
    if ok:
        print("Session revoked.")
        return 0
    print("Session not found.")
    return 1


def cmd_session(args):
    """Manage ephemeral remote sessions."""
    # Load the effective env first: the share-link URL is derived from
    # DUCK_DOMAIN / NGINX_ENABLED / TLS_ENABLED / LANDING_PORT which
    # live in .env/config.env — without this the printed link points
    # at 127.0.0.1 even on a domain-fronted deployment.
    from vnc_remote_secure.core.config import load_env_file
    load_env_file()
    # Profile defaults (NGINX_ENABLED, TLS_ENABLED) must also apply:
    # a hardened-profile deployment has them locked to true even when
    # the operator never wrote them into .env.
    from vnc_remote_secure.security.profiles import apply_profile
    apply_profile()
    from vnc_remote_secure.security.ephemeral_sessions import (
        get_session_store,
    )

    store = get_session_store()
    action = args.session_action
    if action == 'create':
        return _session_create(store, args)
    if action == 'list':
        return _session_list(store, args)
    if action == 'revoke':
        return _session_revoke(args, store)
    print(f"Unknown session action: {action}")
    return 1
