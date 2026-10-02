"""``vnc-remote system-user`` — manage runtime OS accounts.

Thin transport over ``engine.application.system_users`` — the same
use cases behind ``POST/DELETE /api/v1/system-users``. Reserved names
and the current process account are protected inside the use case;
passwords are prompted via getpass — never accepted on argv
(``ps``-visible).
"""

import sys

from vnc_remote_secure.cli._common import (
    _cli_actor,
    _prompt_password,
)


def cmd_system_user(args) -> int:
    """Dispatch system-user sub-actions."""
    from vnc_remote_secure.engine.application import system_users
    from vnc_remote_secure.engine.domain.decision import UseCaseError

    action = getattr(args, "system_user_action", None)

    if action == "create":
        password = _prompt_password()
        if getattr(args, "dry_run", False):
            print(f"[DRY RUN] Would create system user " f"'{args.username}'")
            return 0
        try:
            system_users.create_system_user(_cli_actor(), args.username, password)
        except UseCaseError as e:
            print(f"Error: {e.detail or e.code}", file=sys.stderr)
            return 1
        print(f"System user '{args.username}' created.")
        return 0

    if action == "delete":
        if getattr(args, "dry_run", False):
            print(f"[DRY RUN] Would delete system user " f"'{args.username}'")
            return 0
        try:
            system_users.delete_system_user(_cli_actor(), args.username)
        except UseCaseError as e:
            print(f"Error: {e.detail or e.code}", file=sys.stderr)
            return 1
        print(f"System user '{args.username}' deleted.")
        return 0

    print(f"Unknown system-user action: {action}")
    return 1
