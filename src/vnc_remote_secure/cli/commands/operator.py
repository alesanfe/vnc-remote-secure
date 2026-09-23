"""``vnc-remote operator`` — manage multi-operator accounts.

Operator accounts (``security/operator_users``) authenticate to the
portal and management UI with per-role permissions; the env
credentials remain the bootstrap admin. Passwords are prompted via
getpass — never accepted on argv (``ps``-visible).
"""
import getpass
import json


def _prompt_password(confirm=True):
    """Read a password interactively; empty aborts."""
    pw = getpass.getpass('Password: ')
    if not pw:
        raise SystemExit('Password must not be empty')
    if confirm and pw != getpass.getpass('Confirm password: '):
        raise SystemExit('Passwords do not match')
    return pw


def cmd_operator(args):
    """Dispatch operator sub-actions."""
    from vnc_remote_secure.security import operator_users as ops
    action = getattr(args, 'operator_action', None)

    if action == 'list':
        users = ops.list_users()
        if getattr(args, 'json', False):
            print(json.dumps({'operators': users}, indent=2))
            return 0
        if not users:
            print('No operator accounts — the env credentials '
                  '(bootstrap admin) are the only login.')
            return 0
        print(f"{'USERNAME':<24} {'ROLE':<10} {'STATUS':<10}")
        for u in users:
            print(f"{u['username']:<24} {u['role']:<10} "
                  f"{'disabled' if u['disabled'] else 'active':<10}")
        return 0

    if action == 'add':
        try:
            ops.add_user(args.username,
                         _prompt_password(), args.role)
        except ValueError as e:
            print(f'Error: {e}')
            return 2
        print(f"Operator '{args.username}' added (role={args.role}).")
        return 0

    if action == 'remove':
        if ops.remove_user(args.username):
            print(f"Operator '{args.username}' removed.")
            return 0
        print(f"Operator '{args.username}' not found.")
        return 1

    if action == 'passwd':
        if not ops.set_password(args.username, _prompt_password()):
            print(f"Operator '{args.username}' not found.")
            return 1
        print(f"Password updated for '{args.username}'.")
        return 0

    if action == 'role':
        if not ops.set_role(args.username, args.role):
            print(f"Operator '{args.username}' not found or bad role.")
            return 1
        print(f"Role of '{args.username}' set to {args.role}.")
        return 0

    if action in ('disable', 'enable'):
        if not ops.set_disabled(args.username, action == 'disable'):
            print(f"Operator '{args.username}' not found.")
            return 1
        print(f"Operator '{args.username}' {action}d.")
        return 0

    print('Usage: vnc-remote operator {add|remove|list|passwd|role|'
          'disable|enable} ...')
    return 2
