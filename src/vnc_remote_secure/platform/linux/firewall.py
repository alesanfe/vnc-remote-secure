"""Linux firewall management via UFW or nftables.

Prefers UFW when available and falls back to nftables. All commands
require root privileges.
"""
import shutil
import subprocess

from vnc_remote_secure.core.exceptions import PlatformError


def _have_ufw():
    return shutil.which('ufw') is not None


def _have_nft():
    return shutil.which('nft') is not None


def configure_firewall(port, protocol='tcp'):
    """Allow inbound traffic on ``port``/``protocol``.

    Returns ``True`` on success. Raises :class:`PlatformError` if no
    supported firewall backend is available.
    """
    if _have_ufw():
        result = subprocess.run(
            ['ufw', 'allow', f'{port}/{protocol}'],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    if _have_nft():
        result = subprocess.run(
            ['nft', 'add', 'rule', 'inet', 'filter', 'input',
             'tcp', 'dport', str(port), 'accept'] if protocol == 'tcp'
            else ['nft', 'add', 'rule', 'inet', 'filter', 'input',
                  'udp', 'dport', str(port), 'accept'],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    raise PlatformError("No supported firewall backend (ufw/nftables) found")


def remove_firewall_rule(name):
    """Remove a firewall rule by name or port spec.

    For UFW the ``name`` is the original allow spec (e.g. ``5900/tcp``).
    For nftables the ``name`` is treated as a port spec.
    """
    if _have_ufw():
        result = subprocess.run(
            ['ufw', 'delete', 'allow', name],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    if _have_nft():
        # nftables does not have named rules; best-effort flush.
        result = subprocess.run(
            ['nft', 'delete', 'rule', 'inet', 'filter', 'input',
             'handle', name],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    raise PlatformError("No supported firewall backend (ufw/nftables) found")


def list_firewall_rules():
    """Return a list of currently configured firewall rules.

    Each entry is a string as reported by the backend.
    """
    if _have_ufw():
        result = subprocess.run(
            ['ufw', 'status', 'verbose'],
            capture_output=True, text=True,
        )
        rules = []
        for line in result.stdout.splitlines():
            if 'ALLOW' in line or 'DENY' in line:
                rules.append(line.strip())
        return rules
    if _have_nft():
        result = subprocess.run(
            ['nft', 'list', 'ruleset'],
            capture_output=True, text=True,
        )
        return [line.strip() for line in result.stdout.splitlines()
                if line.strip()]
    return []
