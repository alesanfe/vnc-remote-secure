"""Canonical capability registry — metadata for every permission.

``ephemeral_sessions`` owns the enforcement constants
(``PERM_*``/``ALL_PERMISSIONS``/``_PERMISSION_EXPANSION``); this module
is the *catalog* around them: each permission gets a resource, a risk
rating, the umbrellas that imply it, and a description. Generated
docs, posture output and the negative-test matrix all read from here,
so a permission that exists in enforcement but not in the catalog (or
vice versa) fails the contract test — it can never be silently
unregistered or unenforced.
"""

from dataclasses import dataclass

from vnc_remote_secure.security.ephemeral_sessions import (
    _PERMISSION_EXPANSION,
    ALL_PERMISSIONS,
)


@dataclass(frozen=True)
class Capability:
    """A registered permission with its audit metadata."""
    name: str
    resource: str          # 'desktop', 'terminal', 'audio', 'gamepad',
                           # 'files', 'admin'
    risk: str              # 'low' | 'medium' | 'high'
    description: str
    umbrella: bool = False  # grants its expansion members


_CATALOG: tuple[Capability, ...] = (
    Capability('view', 'desktop', 'low',
               'Read the framebuffer (watch the desktop)'),
    Capability('control', 'desktop', 'high',
               'Full input control (implies keyboard+pointer)',
               umbrella=True),
    Capability('keyboard', 'desktop', 'high',
               'Send key events to the desktop'),
    Capability('pointer', 'desktop', 'high',
               'Send mouse events to the desktop'),
    Capability('clipboard', 'desktop', 'medium',
               'Full clipboard (implies clipboard_read+write)',
               umbrella=True),
    Capability('clipboard_write', 'desktop', 'medium',
               'Push local clipboard text to the remote host'),
    Capability('clipboard_read', 'desktop', 'medium',
               'Read clipboard text coming from the remote host'),
    Capability('file_transfer', 'files', 'medium',
               'Transfer files to/from the remote host'),
    Capability('terminal', 'terminal', 'high',
               'Full terminal (implies terminal_view+write)',
               umbrella=True),
    Capability('terminal_view', 'terminal', 'medium',
               'Open a terminal session, read-only builtins only'),
    Capability('terminal_write', 'terminal', 'high',
               'Execute arbitrary commands in the terminal '
               '(implies terminal_view)', umbrella=True),
    Capability('audio', 'audio', 'low',
               'Listen to the remote audio stream'),
    Capability('gamepad', 'gamepad', 'medium',
               'Attach a gamepad via USB passthrough'),
    Capability('admin', 'admin', 'high',
               'All administrative operations (implies admin_*)',
               umbrella=True),
    Capability('admin_users', 'admin', 'high',
               'Create and delete system users'),
    Capability('admin_config', 'admin', 'medium',
               'Read and modify deployment configuration'),
    Capability('admin_audit', 'admin', 'medium',
               'Read and verify the audit log'),
)


CAPABILITIES: dict[str, Capability] = {c.name: c for c in _CATALOG}


def canonical(name: str) -> str | None:
    """Resolve ``resource:action``/alias forms to a canonical name.

    Mirrors ``EphemeralSession.has_permission`` normalization: the
    composite ``resource_action`` wins ('terminal:write' ->
    'terminal_write'), then the bare action, then the bare resource.
    """
    if name in CAPABILITIES:
        return name
    if ':' in name:
        res, action = name.split(':', 1)
        composite = f'{res}_{action}'
        for candidate in (composite, action, res):
            if candidate in CAPABILITIES:
                return candidate
    return None


def describe(name: str) -> dict | None:
    """Registry entry plus the umbrellas that imply it — or None."""
    cap = CAPABILITIES.get(name)
    if cap is None:
        return None
    implied_by = [u for u, members in _PERMISSION_EXPANSION.items()
                  if name in members]
    return {
        'name': cap.name,
        'resource': cap.resource,
        'risk': cap.risk,
        'description': cap.description,
        'umbrella': cap.umbrella,
        'implies': sorted(_PERMISSION_EXPANSION.get(cap.name, ())),
        'implied_by': implied_by,
    }


def unregistered() -> set[str]:
    """Enforced permissions missing from the catalog (must be empty)."""
    return ALL_PERMISSIONS - set(CAPABILITIES)
