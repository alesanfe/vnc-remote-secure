"""Tab completion helpers for the web terminal.

Owns the client-facing completion surface: the per-OS
``COMMON_COMMANDS`` builtin list, the command-prefix completer (with
the Windows ``where`` PATH lookup) and the cwd-confined path-glob
completer that rejects control characters and directory escapes.

``services.terminal`` re-exports every name here so existing callers
and tests keep resolving them at the old path.
"""

import glob
import logging
import os

from vnc_remote_secure.services.terminal_common import _config

logger = logging.getLogger(__name__)

# Common commands for tab completion (no duplicates)
if os.name == "posix":
    COMMON_COMMANDS = [
        "ls",
        "cd",
        "echo",
        "cat",
        "cp",
        "rm",
        "mv",
        "mkdir",
        "rmdir",
        "ps",
        "kill",
        "ip",
        "ss",
        "netstat",
        "ping",
        "traceroute",
        "uname",
        "python",
        "python3",
        "pip",
        "git",
        "node",
        "npm",
        "which",
        "grep",
        "find",
        "sort",
        "env",
        "export",
        "hostname",
        "whoami",
        "clear",
        "head",
        "tail",
        "df",
        "du",
        "top",
        "systemctl",
        "curl",
        "wget",
        "tar",
        "chmod",
        "chown",
        "ssh",
        "scp",
        "bash",
        "sh",
        "exit",
        "help",
    ]
else:
    COMMON_COMMANDS = [
        "dir",
        "cd",
        "echo",
        "type",
        "copy",
        "del",
        "move",
        "ren",
        "mkdir",
        "rmdir",
        "tasklist",
        "taskkill",
        "ipconfig",
        "netstat",
        "ping",
        "tracert",
        "systeminfo",
        "python",
        "python3",
        "pip",
        "git",
        "node",
        "npm",
        "where",
        "findstr",
        "sort",
        "set",
        "setx",
        "hostname",
        "whoami",
        "ver",
        "vol",
        "tree",
        "attrib",
        "fc",
        "powershell",
        "cmd",
        "cls",
        "exit",
        "help",
        "color",
        "title",
        "prompt",
        "netsh",
        "sc",
        "wmic",
        "chkdsk",
        "format",
        "label",
        "subst",
    ]


def _complete_windows_command(prefix):
    """Complete a command prefix using common commands and PATH lookup."""
    suggestions = [c for c in COMMON_COMMANDS if c.startswith(prefix.lower())]
    # Also match executables in PATH ('where' is Windows-only; on POSIX
    # 'which' works but COMMON_COMMANDS already covers the usual verbs)
    if os.name != "posix" and _config()["webterm_shell"] == "cmd.exe":
        try:
            from vnc_remote_secure.core.processes import run_cmd

            result = run_cmd(
                ["where", prefix + "*"], capture_output=True, text=True, timeout=5, check=False
            )
            for line in result.stdout.strip().split("\n"):
                if line:
                    name = os.path.basename(line.strip()).replace(".exe", "").replace(".EXE", "")
                    if name and name not in suggestions:
                        suggestions.append(name)
        except Exception as e:
            logger.debug("Tab completion via 'where' failed: %s", e)
    return suggestions


def _complete_path_glob(input_str, cwd):
    """Complete a file/directory argument via glob, constrained to cwd tree.

    Returns a list of suggestions, or None when the input is rejected
    (contains null/control characters) so the caller can send an empty
    completion response.
    """
    parts = input_str.split()
    last_word = parts[-1]
    # Sanitize: reject null bytes and control characters
    if "\x00" in last_word or any(ord(c) < 32 for c in last_word):
        return None
    # Determine the directory to search
    if os.path.isabs(last_word):
        search_dir = os.path.dirname(last_word)
        prefix = os.path.basename(last_word)
    else:
        search_dir = cwd
        prefix = last_word

    if not os.path.isdir(search_dir):
        search_dir = cwd

    # Resolve and constrain to cwd tree to prevent arbitrary traversal.
    # Use ``real_cwd + os.sep`` so sibling directories sharing a prefix
    # (e.g. /home/app and /home/apple) are not matched.
    try:
        real_search = os.path.realpath(search_dir)
        real_cwd = os.path.realpath(cwd)
        if real_search != real_cwd and not real_search.startswith(real_cwd + os.sep):
            search_dir = cwd
    except (OSError, ValueError) as e:
        logger.debug("Path validation failed: %s", e)
        search_dir = cwd

    suggestions = []
    try:
        pattern = os.path.join(search_dir, prefix + "*")
        for entry in glob.glob(pattern):
            name = os.path.basename(entry)
            if os.path.isdir(entry):
                name += os.sep
            suggestions.append(name)
    except Exception as e:
        logger.debug("Tab completion via glob failed: %s", e)
    return suggestions
