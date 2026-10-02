"""``vnc-remote operator`` — manage multi-operator accounts.

Operator accounts (``security/operator_users``) authenticate to the
portal and management UI with per-role permissions; the env
credentials remain the bootstrap admin. Passwords are prompted via
getpass — never accepted on argv (``ps``-visible).
"""

import json

from vnc_remote_secure.cli._common import (
    _audit_cli,
    _cli_actor,
    _prompt_password,
)


def _op_list(args) -> int:
    from vnc_remote_secure.security import operator_users as ops

    users = ops.list_users()
    if getattr(args, "json", False):
        print(json.dumps({"operators": users}, indent=2))
        return 0
    if not users:
        print("No operator accounts — the env credentials " "(bootstrap admin) are the only login.")
        return 0
    print(f"{'USERNAME':<24} {'ROLE':<10} {'STATUS':<10}")
    for u in users:
        print(
            f"{u['username']:<24} {u['role']:<10} "
            f"{'disabled' if u['disabled'] else 'active':<10}"
        )
    return 0


def _op_add(args) -> int:
    from vnc_remote_secure.security import operator_users as ops

    try:
        ops.add_user(args.username, _prompt_password(), args.role)
    except ValueError as e:
        print(f"Error: {e}")
        return 2
    _audit_cli("operator_created", "success", f"target={args.username} role={args.role}")
    print(f"Operator '{args.username}' added (role={args.role}).")
    return 0


def _op_remove(args) -> int:
    from vnc_remote_secure.security import operator_users as ops

    if ops.remove_user(args.username):
        _audit_cli("operator_deleted", "success", f"target={args.username}")
        print(f"Operator '{args.username}' removed.")
        return 0
    print(f"Operator '{args.username}' not found.")
    return 1


def _op_passwd(args) -> int:
    from vnc_remote_secure.security import operator_users as ops

    if not ops.set_password(args.username, _prompt_password()):
        print(f"Operator '{args.username}' not found.")
        return 1
    _audit_cli("operator_updated", "success", f"target={args.username} password")
    print(f"Password updated for '{args.username}'.")
    return 0


def _op_role(args) -> int:
    from vnc_remote_secure.security import operator_users as ops

    if not ops.set_role(args.username, args.role):
        print(f"Operator '{args.username}' not found or bad role.")
        return 1
    _audit_cli("operator_updated", "success", f"target={args.username} role={args.role}")
    print(f"Role of '{args.username}' set to {args.role}.")
    return 0


def _op_set_disabled(args, action: str) -> int:
    from vnc_remote_secure.security import operator_users as ops

    if not ops.set_disabled(args.username, action == "disable"):
        print(f"Operator '{args.username}' not found.")
        return 1
    _audit_cli("operator_updated", "success", f"target={args.username} {action}d")
    print(f"Operator '{args.username}' {action}d.")
    return 0


def _op_disable(args) -> int:
    return _op_set_disabled(args, "disable")


def _op_enable(args) -> int:
    return _op_set_disabled(args, "enable")


# Restore / session revocation go through the shared use cases —
# the tombstone, last-admin and job-ledger rules must match the
# API exactly (the local shell is the auth boundary, so the
# step-up policy is satisfied by the shell itself).
def _op_restore(args) -> int:
    from vnc_remote_secure.engine.application.operators import (
        restore_operator,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        restore_operator(_cli_actor(), args.username)
    except UseCaseError as e:
        print(f"Error: {e.detail or e.code}")
        return 1
    print(
        f"Operator '{args.username}' restored (disabled — set a "
        "new password with 'operator passwd' and re-enable)."
    )
    return 0


def _op_revoke_sessions(args) -> int:
    from vnc_remote_secure.engine.application.operators import (
        revoke_sessions,
    )
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    try:
        revoke_sessions(_cli_actor(), args.username)
    except UseCaseError as e:
        print(f"Error: {e.detail or e.code}")
        return 1
    print(f"All sessions for '{args.username}' revoked.")
    return 0


def cmd_operator(args) -> int:
    """Dispatch operator sub-actions."""
    action = getattr(args, "operator_action", None)
    handlers = {
        "list": _op_list,
        "add": _op_add,
        "remove": _op_remove,
        "passwd": _op_passwd,
        "role": _op_role,
        "disable": _op_disable,
        "enable": _op_enable,
        "restore": _op_restore,
        "revoke-sessions": _op_revoke_sessions,
    }
    handler = handlers.get(action) if isinstance(action, str) else None
    if handler is None:
        print(
            "Usage: vnc-remote operator {add|remove|list|passwd|role|"
            "disable|enable|restore|revoke-sessions} ..."
        )
        return 2
    return handler(args)
