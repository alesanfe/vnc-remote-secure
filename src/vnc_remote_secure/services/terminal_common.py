"""Shared plumbing for the web-terminal service modules.

The terminal implementation is split by responsibility across
``terminal_completion`` (tab completion), ``terminal_spawn`` (child
process sandbox/argv), ``terminal_session`` (the WebSocket session
object) and ``terminal`` (FastAPI entry point + public facade). This
module holds the one piece they all share: the lazy runtime-config
accessor.

Importing it also loads the ``.env`` file — the same import-time side
effect ``services.terminal`` always had, so every entry point that
reaches the terminal internals resolves credentials from the
environment exactly like before.
"""

from vnc_remote_secure.core.config import load_env_file

# Load configuration from .env file (never hardcode credentials)
load_env_file()


def _config():
    """Return the runtime config lazily so .env changes take effect on each call."""
    from vnc_remote_secure.core.config import get_config

    return get_config()
