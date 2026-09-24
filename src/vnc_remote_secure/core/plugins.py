"""Plugin registry — the declared contract for optional services.

Optional features are plugins, not ad-hoc config checks scattered
through the service manager: each declares the config key that gates
it, the capability a session needs to reach it, its platform
constraints, and whether it is on by default. The service manager
iterates this registry instead of hardcoding ``config.get(...)``
checks, and posture/doctor can enumerate the attack surface from one
place.

Core services (``vnc``, ``terminal``, ``novnc``, ``landing``,
``websockify``) are NOT plugins — they are the product.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class OptionalPlugin:
    """An opt-in service with a declared security contract.

    Attributes:
        name: Service-manager service name (PID file, audit events).
        config_key: Effective-config boolean that enables it.
        permission: Canonical capability a session must hold to use
            the plugin's surface (``None`` = no session surface).
        description: Human description for doctor/posture output.
        default_enabled: Value when the config key is absent.
        linux_only: Skip silently on Windows (no binary to supervise).
    """
    name: str
    config_key: str
    permission: str | None
    description: str
    default_enabled: bool = False
    linux_only: bool = False


# Declaration order is also start order — keep it stable so service
# startup sequencing is reproducible.
_PLUGINS: tuple[OptionalPlugin, ...] = (
    OptionalPlugin(
        'health', 'health_web_enabled', 'metrics:read',
        'Standalone health/metrics/audit HTTP server on :8080',
        default_enabled=True),
    OptionalPlugin(
        'user_ui', 'user_ui_enabled', 'user:manage',
        'Flask user-management UI'),
    OptionalPlugin(
        'audio', 'audio_stream_enabled', 'audio:listen',
        'PulseAudio -> Icecast audio stream (Linux only)'),
    OptionalPlugin(
        'gamepad', 'gamepad_enabled', 'gamepad:attach',
        'VirtualHere / USB-IP gamepad passthrough'),
    OptionalPlugin(
        'nginx', 'nginx_enabled', None,
        'Reverse proxy + TLS terminator', linux_only=True),
)


def iter_plugins() -> tuple[OptionalPlugin, ...]:
    """All declared optional plugins, in start order."""
    return _PLUGINS


def plugin_for(service: str) -> OptionalPlugin | None:
    """The plugin declaring *service*, or None for core services."""
    for p in _PLUGINS:
        if p.name == service:
            return p
    return None


def plugin_enabled(plugin: OptionalPlugin, config: dict,
                   is_windows: bool) -> bool:
    """Whether *plugin* should start under *config*."""
    if plugin.linux_only and is_windows:
        return False
    return bool(config.get(plugin.config_key, plugin.default_enabled))


def enabled_plugins(config: dict, is_windows: bool) -> list[str]:
    """Names of optional plugins enabled under *config*."""
    return [p.name for p in _PLUGINS
            if plugin_enabled(p, config, is_windows)]


def attack_surface(config: dict, is_windows: bool) -> dict:
    """Enabled plugin -> required capability, for posture reports."""
    return {
        p.name: p.permission for p in _PLUGINS
        if plugin_enabled(p, config, is_windows)
    }
