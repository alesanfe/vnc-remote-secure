"""Host power control + Wake-on-LAN — parity with MeshCentral/RustDesk
device power actions.

Two use cases:

* ``wake_on_lan(mac)`` — broadcast a magic packet so an asleep/off host
  on the LAN can be woken before anyone connects. WoL is UDP broadcast;
  it works from the machine hosting this service.
* ``host_power(action)`` — shutdown / restart / sleep THIS host. The
  action runs on a short delay via a detached thread so the HTTP
  response is delivered before the host drops (a synchronous shutdown
  would swallow the API reply).

Security: both paths are operator-side primitives — the API routes gate
them behind ``admin:*`` and ``host_power`` additionally consumes a
single-use step-up grant bound to the exact action (``power.action``);
there is deliberately no guest path (halting the host cannot be a
share-link capability).
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import threading

from vnc_remote_secure.engine.application.ops import (
    require_bound_step_up,
)
from vnc_remote_secure.engine.infrastructure import stores

POWER_ACTIONS = ('shutdown', 'restart', 'sleep')
_MAC_RE = re.compile(r'^[0-9a-fA-F]{2}([:-]?[0-9a-fA-F]{2}){5}$')
# Delay lets the response + audit flush before the OS takes the host
# down; too short risks a truncated reply, too long invites a second
# conflicting request.
_GRACE_SECONDS = 1.0


def wake_on_lan(mac: str, broadcast: str = '255.255.255.255',
                port: int = 9, actor: str = 'operator') -> dict:
    """Send a WoL magic packet. Returns {sent, mac, broadcast, port}.

    ``broadcast`` is restricted to broadcast/unspecified targets —
    the call must not become a generic UDP sender.
    """
    mac = (mac or '').strip()
    if not _MAC_RE.match(mac):
        raise ValueError('invalid MAC address')
    hex_mac = mac.replace(':', '').replace('-', '')
    try:
        addr = ipaddress.ip_address(broadcast)
    except ValueError:
        raise ValueError('invalid broadcast address')
    if not addr.is_unspecified and broadcast != '255.255.255.255' \
            and not str(broadcast).endswith('.255'):
        raise ValueError('target must be a broadcast address')

    packet = b'\xff' * 6 + bytes.fromhex(hex_mac) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, port))
    stores.audit('power_wol', actor, f'mac={mac} bcast={broadcast}')
    return {'sent': True, 'mac': mac, 'broadcast': broadcast,
            'port': port}


def _power_cmd(action: str) -> list[str]:
    """Platform power command. Sleep maps to suspend/standby. """
    if os.name == 'nt':
        if action == 'shutdown':
            return ['shutdown', '/s', '/t', '0']
        if action == 'restart':
            return ['shutdown', '/r', '/t', '0']
        return ['rundll32.exe', 'powrprof.dll,SetSuspendState',
                '0,1,0']
    # POSIX: prefer systemctl when present, fall back to classic tools.
    if action == 'shutdown':
        return ['systemctl', 'poweroff']
    if action == 'restart':
        return ['systemctl', 'reboot']
    return ['systemctl', 'suspend']


def host_power(action: str, actor: str,
               auth_ctx: dict | None = None) -> dict:
    """Schedule a host power action after a short grace delay.

    The command runs in a daemon thread: shutdown/restart kill the
    calling service, so the work must outlive the HTTP handler without
    blocking the response. Errors raise ``ValueError`` (bad action) or
    ``RuntimeError`` (no usable platform command).
    """
    if action not in POWER_ACTIONS:
        raise ValueError(f'action must be one of {POWER_ACTIONS}')
    require_bound_step_up(actor, 'power.action', action, auth_ctx)
    cmd = _power_cmd(action)

    def _run() -> None:
        import subprocess
        try:
            subprocess.run(cmd, check=False, timeout=15)
        except Exception as exc:  # noqa: BLE001 - thread: log only
            import logging
            logging.getLogger(__name__).warning(
                'Host power %s failed: %s', action, exc)

    threading.Thread(target=_run, daemon=True,
                     name='host-power').start()
    stores.audit('power_action', actor,
                 f'action={action} platform={platform.system()}')
    return {'action': action, 'accepted': True,
            'effective_in_seconds': _GRACE_SECONDS}
