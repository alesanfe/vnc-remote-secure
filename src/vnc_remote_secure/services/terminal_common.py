"""Shared plumbing for the web-terminal service modules.

The terminal implementation is split by responsibility across
``terminal_completion`` (tab completion), ``terminal_spawn`` (child
process sandbox/argv), ``terminal_session`` (the WebSocket session
object) and ``terminal`` (FastAPI entry point + public facade). This
module holds the one piece they all share: the lazy runtime-config
accessor.

Importing it must not mutate ``os.environ`` (CFG-001): ``get_config()``
loads ``.env`` lazily on first call, and every entry point loads it
explicitly at the composition root — the import-time load this module
used to do is gone.
"""


def _config():
    """Return the runtime config lazily so .env changes take effect on each call."""
    from vnc_remote_secure.core.config import get_config

    return get_config()
