"""``vnc-remote power`` — host power actions + Wake-on-LAN.

Thin transport over ``engine.application.power``: ``power action``
shuts down / restarts / suspends THIS host (the action runs on a
grace-delay thread so the reply is printed before the host drops);
``power wol`` broadcasts a magic packet to wake a LAN machine.
"""

import json
import sys

from vnc_remote_secure.cli._common import _cli_actor


def _power_action(args) -> int:
    from vnc_remote_secure.engine.application.power import host_power

    if getattr(args, "dry_run", False):
        print(f"[DRY RUN] Would {args.action} this host")
        return 0
    if not getattr(args, "yes", False):
        # Interactive confirmation — halting the host kills the portal
        # and every live session; never do it silently.
        try:
            answer = input(
                f"{args.action} THIS host? The portal and all sessions " "will drop. [y/N] "
            )
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1
    try:
        result = host_power(args.action, _cli_actor())
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    else:
        print(
            f"Host {result['action']} scheduled — effective in "
            f"{result['effective_in_seconds']}s."
        )
    return 0


def _power_wol(args) -> int:
    from vnc_remote_secure.engine.application.power import wake_on_lan

    if getattr(args, "dry_run", False):
        print(f"[DRY RUN] Would send WoL magic packet to {args.mac}")
        return 0
    try:
        result = wake_on_lan(args.mac, args.broadcast, args.port, actor=_cli_actor())
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    else:
        print(f"WoL packet sent to {result['mac']} via " f"{result['broadcast']}:{result['port']}.")
    return 0


def cmd_power(args) -> int:
    """Host power actions and Wake-on-LAN."""
    action = getattr(args, "power_action", None)
    if action == "action":
        return _power_action(args)
    if action == "wol":
        return _power_wol(args)
    print(f"Unknown power action: {action}")
    return 1
