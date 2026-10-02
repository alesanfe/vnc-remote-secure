"""Child-process spawning and sandboxing for the web terminal.

Everything about *how a terminal command becomes a subprocess* lives
here, distinct from the session/protocol handling in
``terminal_session``:

- ``_build_child_env``: sanitized environment (no credential vars).
- ``_child_rlimits``: POSIX ``preexec_fn`` bounding a child's
  processes/address-space/CPU/descriptors/file size (no core dumps).
- ``_restricted_user_prefix``: optional ``WEBTERM_USER`` uid drop via
  setpriv/runuser when running as root.
- ``_bwrap_usable`` / ``_sandbox_prefix``: bubblewrap user-namespace
  fallback that tmpfs-masks the directories holding service secrets.
- ``_ALLOWED_SHELLS`` / ``_shell_allowed`` / ``_build_subprocess_args``:
  the WEBTERM_SHELL allowlist and the per-platform argv builder.
- ``_assign_to_kill_job``: Windows Job Object with KILL_ON_JOB_CLOSE so
  spawned shells cannot outlive this service process.
- ``_kill_process_tree``: taskkill /T on Windows, killpg SIGKILL on
  POSIX — grandchildren keep pipes open otherwise.

``services.terminal`` re-exports every name here so existing callers
(audio, doctor) and tests keep resolving them at the old path.
"""

import logging
import os
import sys
from contextlib import suppress

logger = logging.getLogger(__name__)


def _build_child_env():
    """Build a sanitized environment for the child process.

    All credential variables (the canonical ``SECRET_VARS`` list —
    VNC_PASSWORD, TTYD_PASSWD, TOTP_SECRET, HEALTH_AUTH_TOKEN,
    BACKUP_PASSWORD, webhook URLs, SMTP passwords, etc.) are removed
    so they are not exfiltrable via `set`/`env` commands.
    """
    from vnc_remote_secure.security.redaction import SECRET_VARS

    return {k: v for k, v in os.environ.items() if k not in SECRET_VARS}


def _child_rlimits():
    """Return a ``preexec_fn`` bounding a terminal child's resources.

    POSIX only. Limits inherited across exec (setpriv/runuser/exec),
    so they apply to the shell and its descendants:

    - ``RLIMIT_NPROC`` — per-uid process count (fork bombs).
    - ``RLIMIT_AS`` — address space (memory exhaustion).
    - ``RLIMIT_CPU`` — CPU seconds (a cmd can outpace CMD_TIMEOUT
      wall-clock only up to this).
    - ``RLIMIT_NOFILE`` — descriptor count.
    - ``RLIMIT_FSIZE`` — a runaway `> file` cannot fill the disk.
    - ``RLIMIT_CORE`` — core dumps disabled (they can embed secrets).
    """

    def _apply():
        # POSIX-only module; unreachable on Windows (guarded above).
        import resource  # pylint: disable=import-error

        limits = (
            (resource.RLIMIT_NPROC, 128),
            (resource.RLIMIT_AS, 1 << 30),  # 1 GiB
            (resource.RLIMIT_CPU, 300),
            (resource.RLIMIT_NOFILE, 256),
            (resource.RLIMIT_FSIZE, 256 << 20),  # 256 MiB
            (resource.RLIMIT_CORE, 0),
        )
        for res, soft in limits:
            try:
                hard = resource.getrlimit(res)[1]
                cap = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
                resource.setrlimit(res, (cap, cap))
            except (OSError, ValueError):
                # A limit the platform lacks must not abort the spawn.
                pass

    return _apply


def _restricted_user_prefix():
    """Return argv prefix to drop privileges to ``WEBTERM_USER``.

    When ``WEBTERM_USER`` names an existing account and this process
    runs as root, terminal commands are spawned as that user instead
    of the service account — the shell can no longer read the
    service's secrets, PID files or other services' state. Prefers
    ``setpriv`` (no PAM), falls back to ``runuser``. Returns ``None``
    when privilege dropping is unavailable or not configured.
    """
    import pwd  # pylint: disable=import-error
    import shutil as _shutil

    user = os.environ.get("WEBTERM_USER", "").strip()
    if not user:
        return None
    if os.geteuid() != 0:  # pylint: disable=no-member
        logger.warning(
            "WEBTERM_USER=%s ignored — not running as root; terminal "
            "commands execute as the service user",
            user,
        )
        return None
    try:
        from vnc_remote_secure.core.validation import validate_username

        validate_username(user)
    except (ImportError, ValueError) as exc:
        logger.warning("WEBTERM_USER rejected: %s", exc)
        return None
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        logger.warning("WEBTERM_USER=%s does not exist — ignoring", user)
        return None
    setpriv = _shutil.which("setpriv")
    if setpriv:
        return [
            setpriv,
            "--reuid",
            str(pw.pw_uid),
            "--regid",
            str(pw.pw_gid),
            "--clear-groups",
            "--",
        ]
    runuser = _shutil.which("runuser")
    if runuser:
        return [runuser, "-u", user, "--"]
    logger.warning(
        "WEBTERM_USER=%s configured but neither setpriv nor runuser "
        "found — terminal runs as the service user",
        user,
    )
    return None


_BWRAP_USABLE = None


def _bwrap_usable(bwrap: str) -> bool:
    """Probe once whether unprivileged user namespaces work.

    ``bwrap --dev-bind / / -- true`` is the minimal namespace setup —
    when the kernel forbids unprivileged userns (e.g.
    ``kernel.unprivileged_userns_clone=0``) the probe fails and we fall
    back instead of erroring every terminal command.
    """
    global _BWRAP_USABLE
    if _BWRAP_USABLE is not None:
        return _BWRAP_USABLE
    try:
        from vnc_remote_secure.core.processes import run_cmd

        res = run_cmd([bwrap, "--dev-bind", "/", "/", "--", "true"], capture_output=True, timeout=5)
        _BWRAP_USABLE = res.returncode == 0
    except Exception:  # noqa: BLE001 - probe is best-effort
        _BWRAP_USABLE = False
    if not _BWRAP_USABLE:
        logger.warning(
            "bubblewrap present but unprivileged user namespaces are "
            "disabled — terminal sandbox unavailable"
        )
    return _BWRAP_USABLE


def _sandbox_prefix():
    """Return a bubblewrap argv prefix masking secret dirs, or None.

    When the WEBTERM_USER privilege drop is unavailable (the packaged
    systemd unit runs as the unprivileged ``vnc-remote`` user, where
    setpriv/runuser are impossible), unprivileged user namespaces still
    let us hide the directories holding service secrets — auth_secret.
    key, shared_state.db, generated_credentials.env, config.env, SSL
    keys and backups — from the spawned shell. The shell keeps a full
    view of the rest of the filesystem; only the service-owned state
    is masked with tmpfs.
    """
    import shutil as _shutil

    bwrap = _shutil.which("bwrap")
    if not bwrap or not _bwrap_usable(bwrap):
        return None
    try:
        from vnc_remote_secure.core.paths import (
            get_config_dir,
            get_data_dir,
            get_log_dir,
            get_run_dir,
            get_ssl_dir,
        )

        sensitive = [get_run_dir(), get_ssl_dir(), get_config_dir(), get_data_dir(), get_log_dir()]
    except Exception:  # noqa: BLE001 - paths module unavailable
        sensitive = []
    args = [bwrap, "--dev-bind", "/", "/"]
    # Mask every sensitive dir — even the shell's cwd. A cwd inside a
    # masked dir resolves to the empty tmpfs (confusing but secure);
    # skipping the mask would leave the service state readable.
    for d in sensitive:
        args += ["--tmpfs", os.path.realpath(d)]
    args.append("--")
    return args


# Shell allowlist for WEBTERM_SHELL (§6): an arbitrary binary as
# "shell" would execute `binary -c <remote command>` — restricting
# to real shells keeps the env var from becoming a code-exec
# primitive via configuration.
_ALLOWED_SHELLS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "cmd.exe",
        "cmd",
        "powershell.exe",
        "powershell",
        "pwsh.exe",
        "pwsh",
    }
)


def _shell_allowed(shell: str) -> bool:
    """Return True when ``shell`` is in the terminal shell allowlist."""
    return os.path.basename(shell).lower() in _ALLOWED_SHELLS


def _build_subprocess_args(cmd, shell, cwd):
    """Build the subprocess argument list for the configured shell."""
    import shutil as _shutil

    if os.name == "posix":
        # POSIX shell (bash/sh/zsh): the configured WEBTERM_SHELL or a
        # sane fallback — cmd.exe does not exist here.
        if shell and not _shell_allowed(shell):
            logger.warning(
                "WEBTERM_SHELL=%r not in the shell allowlist — " "falling back to bash/sh", shell
            )
            shell = ""
        resolved = (_shutil.which(shell) if shell else None) or _shutil.which("bash") or "/bin/sh"
        # Prefer a real uid drop (strongest); fall back to the
        # bubblewrap filesystem sandbox when the service is non-root.
        prefix = _restricted_user_prefix() or _sandbox_prefix() or []
        return prefix + [resolved, "-c", cmd]
    if shell == "powershell.exe":
        ps_exe = (
            _shutil.which("powershell.exe")
            or _shutil.which("powershell")
            or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )
        return [ps_exe, "-NoProfile", "-NonInteractive", "-Command", cmd]
    cmd_exe = _shutil.which("cmd.exe") or os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
    # NOTE: cmd.exe /c has notoriously inconsistent quote handling
    # (inner quotes may be stripped depending on the command). This is
    # a cmd.exe behaviour, not something this layer can safely fix —
    # wrapping the whole command in quotes breaks paths containing
    # spaces. Users needing complex quoting should set
    # WEBTERM_SHELL=powershell.exe, which takes -Command verbatim.
    return [cmd_exe, "/c", cmd]


_kill_job_handle = None


def _assign_to_kill_job(proc) -> None:
    """Windows: assign ``proc`` to a Job Object with KILL_ON_JOB_CLOSE.

    When the last handle to the job closes — i.e. when this terminal
    service process exits, even abruptly — Windows kills every
    assigned process. Without it, a crashed/killed terminal service
    orphans cmd/powershell children that keep an interactive shell
    alive after the remote command that spawned them is gone. POSIX
    children share the service's process group and are covered by
    the manager's killpg path. Best-effort: nested-job hosts (and
    AppContainer, which uses its own job) can reject the
    assignment — taskkill /T remains the fallback.
    """
    global _kill_job_handle
    if sys.platform != "win32":
        return
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        if _kill_job_handle is None:
            _kill_job_handle = k32.CreateJobObjectW(None, None)
            if not _kill_job_handle:
                return

            class _Basic(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", ctypes.c_uint32),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint32),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", ctypes.c_uint32),
                    ("SchedulingClass", ctypes.c_uint32),
                ]

            class _Io(ctypes.Structure):
                _fields_ = [
                    (k, ctypes.c_uint64)
                    for k in (
                        "ReadOperationCount",
                        "WriteOperationCount",
                        "OtherOperationCount",
                        "ReadTransferCount",
                        "WriteTransferCount",
                        "OtherTransferCount",
                    )
                ]

            class _Ext(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _Basic),
                    ("IoInfo", _Io),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            # JobObjectExtendedLimitInformation = 9,
            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000.
            info = _Ext()
            info.BasicLimitInformation.LimitFlags = 0x2000
            if not k32.SetInformationJobObject(
                _kill_job_handle, 9, ctypes.byref(info), ctypes.sizeof(info)
            ):
                _kill_job_handle = None
                return
        # Resolve a HANDLE: subprocess.Popen exposes _handle; an
        # asyncio subprocess Process carries it under
        # _transport._proc; a bare pid needs OpenProcess
        # (PROCESS_SET_QUOTA|PROCESS_TERMINATE = 0x0101).
        handle = getattr(proc, "_handle", None)
        opened = False
        if handle is None:
            inner = getattr(getattr(proc, "_transport", None), "_proc", None)
            handle = getattr(inner, "_handle", None)
        if handle is None:
            pid = getattr(proc, "pid", None) or (proc if isinstance(proc, int) else None)
            if not pid:
                return
            handle = k32.OpenProcess(0x0101, False, int(pid))
            opened = bool(handle)
            if not handle:
                return
        try:
            if not k32.AssignProcessToJobObject(_kill_job_handle, int(handle)):
                logger.debug(
                    "Job assignment refused for pid %s (nested job?)", getattr(proc, "pid", proc)
                )
        finally:
            if opened:
                k32.CloseHandle(handle)
    except Exception as e:  # noqa: BLE001
        logger.debug("Kill-job unavailable: %s", e)


def _kill_process_tree(proc):
    """Kill ``proc`` and its whole process tree.

    ``proc.kill()`` alone kills only the shell — grandchildren
    (``cmd /c ping``, ``bash -c 'tail -f'``) keep running and keep the
    stdout/stderr pipes open, so the drain threads would block until
    the grandchild exits. On Windows use ``taskkill /T`` (tree kill);
    on POSIX send SIGKILL to the process group.
    """
    try:
        if os.name == "nt":
            from vnc_remote_secure.core.processes import run_cmd

            run_cmd(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=10,
                check=False,
            )
        else:
            import signal

            try:
                # POSIX-only path — pylint: disable=no-member
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:  # ProcessLookupError/PermissionError subclass OSError
                proc.kill()
    except Exception:  # noqa: BLE001 - kill is best-effort
        with suppress(Exception):
            proc.kill()
