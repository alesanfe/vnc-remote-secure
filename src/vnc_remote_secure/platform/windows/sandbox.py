"""AppContainer process sandbox for the Windows web terminal and VNC server.

F-035 mitigation: the web terminal previously spawned shells as the
interactive user with full access to the service's secrets
(``auth_secret.key``, ``shared_state.db``, ``generated_credentials.env``)
because Windows offers no root-less privilege drop and
``CreateProcessWithTokenW`` requires ``SeImpersonatePrivilege``.

An AppContainer child process needs **no** special privileges: a plain
``CreateProcessW`` with ``PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES``
sandboxes the process so it can only touch filesystem locations whose
ACLs name the AppContainer SID (or ALL APPLICATION PACKAGES). The user
profile — where the service state lives — is unreachable: reads of
``auth_secret.key`` and writes to ``shared_state.db`` both fail inside
the sandbox.

Two sandbox profiles share this module:

- ``VncRemoteSecure.Terminal`` (web terminal): **no** network
  capabilities — the spawned shell cannot open sockets at all. It gets
  a scratch working directory under %TEMP% ACL'd to its AppContainer
  SID, plus TEMP/TMP pointed at it so tools still work. Extra
  directories can be exposed read-only via the
  ``TERMINAL_WINDOWS_SANDBOX_DIRS`` env var (semicolon-separated).
- ``VncRemoteSecure.VncServer`` (UltraVNC winvnc.exe): the network
  capabilities ``internetClientServer`` and
  ``privateNetworkClientServer`` so winvnc can bind the RFB port and
  accept incoming connections, plus read-write access to its own
  install directory (``ultravnc.ini`` and ``WinVNC.log`` live next to
  the binary). winvnc is a GUI process that captures the interactive
  desktop — the AppContainer stays in the SAME session and window
  station, so screen capture keeps working (CreateProcessAsUser, the
  previously planned alternative, would need the restricted user's
  credentials and a separate session).

Mode is controlled per child by ``TERMINAL_WINDOWS_SANDBOX`` /
``VNC_WINDOWS_SANDBOX``:

- ``auto`` (default): sandbox; fall back to an unsandboxed spawn with a
  loud warning if CreateProcess fails (keeps things usable on
  exotic Windows builds).
- ``strict``: sandbox; propagate the failure instead of falling back.
- ``off``:   never sandbox.
"""

import ctypes
import logging
import msvcrt
import os
import subprocess
import tempfile
from contextlib import suppress
from ctypes import wintypes

logger = logging.getLogger(__name__)

_APP_CONTAINER_NAME = "VncRemoteSecure.Terminal"
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020003
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x00000102
_STILL_ACTIVE = 259
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JobObjectExtendedLimitInformation = 9

# Well-known capability SIDs (documented literals, winnt.h
# SECURITY_CAPABILITY_*): these are the only capabilities this project
# grants — they let winvnc listen on the RFB port and accept inbound
# connections. Names are matched case-insensitively; any other
# capability name is resolved via DeriveCapabilitySidsFromName.
_WELL_KNOWN_CAPABILITY_SIDS = {
    "internetclient": "S-1-15-3-1",
    "internetclientserver": "S-1-15-3-2",
    "privatenetworkclientserver": "S-1-15-3-3",
}

_appcontainer_sids: dict = {}  # profile name -> (PSID c_void_p, SID string)
_capability_sid_cache: dict = {}  # capability name -> [PSID c_void_p, ...]
_capability_sid_refs: list = []  # PSIDs kept alive — attribute lists borrow them
_granted_dirs: set = set()  # (sid_str, realpath, write)


class _SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", ctypes.c_byte * 48),  # IO_COUNTERS — unused
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _proto():
    """Declare ctypes prototypes — without them, 64-bit HANDLEs and.

    pointers passed positionally are truncated to c_int.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32


def _get_sid(name=_APP_CONTAINER_NAME):
    """Derive (once per name) the AppContainer SID for a stable profile name.

    Returns ``(PSID, SID-string)``. Each distinct profile name maps to a
    distinct AppContainer SID, so ACL grants made for one child do not
    leak into another sandbox.
    """
    cached = _appcontainer_sids.get(name)
    if cached:
        return cached
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # The AppContainer profile/SID APIs live in userenv.dll (documented
    # host); some exports surface elsewhere depending on the build, so
    # probe a short list.
    host = None
    for dll in ("userenv", "kernelbase", "kernel32"):
        try:
            cand = ctypes.WinDLL(dll, use_last_error=True)
            if hasattr(cand, "DeriveAppContainerSidFromAppContainerName"):
                host = cand
                break
        except (OSError, AttributeError):
            continue
    if host is None:
        for dll in ("userenv", "kernelbase", "kernel32"):
            try:
                cand = ctypes.WinDLL(dll, use_last_error=True)
                if hasattr(cand, "CreateAppContainerProfile"):
                    host = cand
                    break
            except (OSError, AttributeError):
                continue
    if host is None:
        raise OSError("AppContainer APIs unavailable on this system")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    sid = ctypes.c_void_p()
    try:
        derive = host.DeriveAppContainerSidFromAppContainerName
    except AttributeError:
        derive = None
    if derive:
        derive.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        derive.restype = ctypes.c_long
        hr = derive(name, ctypes.byref(sid))
        if hr != 0:  # HRESULT S_OK == 0
            raise OSError(
                "DeriveAppContainerSidFromAppContainerName failed: " f"HRESULT {hr:#010x}"
            )
    else:
        create = host.CreateAppContainerProfile
        create.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        create.restype = ctypes.c_long
        hr = create(
            name,
            f"VNC Remote Secure — {name}",
            "Sandboxed child process",
            None,
            0,
            ctypes.byref(sid),
        )
        if hr != 0:
            raise OSError(f"CreateAppContainerProfile failed: HRESULT {hr:#010x}")
    # String form for icacls grants.
    ptr = ctypes.c_void_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(ptr)):
        raise ctypes.WinError(ctypes.get_last_error())
    sid_str = ctypes.wstring_at(ptr.value)
    kernel32.LocalFree(ptr)
    _appcontainer_sids[name] = (sid, sid_str)
    return sid, sid_str


def _scratch_dir(name=_APP_CONTAINER_NAME):
    """Create (once per container) the sandboxed working dir and ACL it."""
    suffix = name.rsplit(".", 1)[-1].lower() or "app"
    path = os.path.join(tempfile.gettempdir(), f"vnc-sandbox-{suffix}")
    _, sid_str = _get_sid(name)
    _grant_dir(path, write=True, sid_str=sid_str)
    return path


def _grant_dir(path, write=False, sid_str=None):
    """Grant an AppContainer SID access to ``path`` via icacls.

    ``sid_str`` selects which container profile gets the grant; the
    default is the terminal container. Everyone holds
    SeChangeNotifyPrivilege, so granting the leaf dir is enough —
    parents need not be readable.
    """
    if sid_str is None:
        sid_str = _get_sid()[1]
    real = os.path.realpath(path)
    key = (sid_str, real, write)
    if key in _granted_dirs:
        return real
    rights = "(OI)(CI)(M)" if write else "(OI)(CI)(RX)"
    os.makedirs(real, exist_ok=True)
    from vnc_remote_secure.core.processes import run_cmd

    res = run_cmd(
        ["icacls", real, "/grant", f"*{sid_str}:{rights}"], capture_output=True, timeout=10
    )
    if res.returncode != 0:
        raise OSError(f"icacls grant on {real} failed: " f"{res.stderr!r}")
    _granted_dirs.add(key)
    return real


def _sid_from_string(sid_str):
    """Convert a SID literal (``S-1-15-3-x``) to a PSID."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    conv = advapi32.ConvertStringSidToSidW
    conv.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    psid = ctypes.c_void_p()
    if not conv(sid_str, ctypes.byref(psid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return psid


def _derive_capability_sids(name):
    """Derive PSIDs for a named capability via userenv.dll.

    Well-known capabilities have fixed SIDs (see
    ``_WELL_KNOWN_CAPABILITY_SIDS``); other capability names derive
    their package capability SID from a name hash inside
    ``DeriveCapabilitySidsFromName``. Only the capability SIDs (not
    the group SIDs) belong in SECURITY_CAPABILITIES.
    """
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    derive = userenv.DeriveCapabilitySidsFromName
    derive.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ctypes.POINTER(wintypes.DWORD),
    ]
    group_sids = ctypes.POINTER(ctypes.c_void_p)()
    group_count = wintypes.DWORD()
    cap_sids = ctypes.POINTER(ctypes.c_void_p)()
    cap_count = wintypes.DWORD()
    if not derive(
        name,
        ctypes.byref(group_sids),
        ctypes.byref(group_count),
        ctypes.byref(cap_sids),
        ctypes.byref(cap_count),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    psids = [ctypes.c_void_p(cap_sids[i]) for i in range(cap_count.value)]
    # Free the group SIDs and the two arrays; the capability PSIDs stay
    # alive in _capability_sid_refs — attribute lists borrow them.
    for i in range(group_count.value):
        kernel32.LocalFree(group_sids[i])
    kernel32.LocalFree(group_sids)
    kernel32.LocalFree(cap_sids)
    return psids


def _capability_sids(names):
    """Resolve capability names to PSIDs for SECURITY_CAPABILITIES."""
    out = []
    for name in names:
        key = name.strip().lower()
        if not key:
            continue
        cached = _capability_sid_cache.get(key)
        if cached is None:
            literal = _WELL_KNOWN_CAPABILITY_SIDS.get(key)
            if literal is not None:
                cached = [_sid_from_string(literal)]
            else:
                cached = _derive_capability_sids(name.strip())
            _capability_sid_cache[key] = cached
            _capability_sid_refs.extend(cached)
        out.extend(cached)
    return out


class SandboxedProcess:
    """Minimal Popen-compatible wrapper around an AppContainer child."""

    def __init__(self, pid, h_process, h_job, stdout_f, stderr_f):
        self.pid = pid
        self._h_process = h_process
        self._h_job = h_job
        self.stdout = stdout_f
        self.stderr = stderr_f
        self.stdin = None
        self.returncode = None
        self._kernel32 = _proto()

    def poll(self):
        """Poll."""
        if self.returncode is not None:
            return self.returncode
        rc = self._kernel32.WaitForSingleObject(self._h_process, 0)
        if rc == _WAIT_OBJECT_0:
            code = wintypes.DWORD()
            self._kernel32.GetExitCodeProcess(self._h_process, ctypes.byref(code))
            self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout=None):
        """Wait."""
        ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
        rc = self._kernel32.WaitForSingleObject(self._h_process, ms)
        if rc == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.pid, timeout)
        code = wintypes.DWORD()
        self._kernel32.GetExitCodeProcess(self._h_process, ctypes.byref(code))
        self.returncode = int(code.value)
        return self.returncode

    def terminate(self):
        """Terminate."""
        # The job has KILL_ON_JOB_CLOSE semantics — terminating the job
        # kills the whole tree the sandboxed shell spawned, which plain
        # TerminateProcess on the root would orphan.
        if self._h_job:
            self._kernel32.TerminateJobObject(self._h_job, 1)
        else:
            self._kernel32.TerminateProcess(self._h_process, 1)

    def kill(self):
        """Kill."""
        self.terminate()

    def __del__(self):
        """Del."""
        for h in (self._h_process, self._h_job):
            if h:
                with suppress(Exception):  # GC path is best-effort
                    self._kernel32.CloseHandle(h)


def _inheritable_handle(fd):
    """Return the OS handle for ``fd`` marked inheritable."""
    os.set_inheritable(fd, True)
    return msvcrt.get_osfhandle(fd)


class _SandboxStdio:
    """stdio plumbing for the sandboxed child.

    The child gets the write ends of stdout/stderr pipes (or NUL when
    nobody drains them) and a NUL stdin. The std handles in
    STARTUPINFO reach the child even with an attribute list present,
    so no HANDLE_LIST attribute is needed (and adding one is rejected
    with ERROR_NOT_SUPPORTED).
    """

    def __init__(self, capture_output):
        self.r_out = self.r_err = None
        self.w_out = self.w_err = None
        if capture_output:
            self.r_out, self.w_out = os.pipe()
            self.r_err, self.w_err = os.pipe()
        # SIM115: the fds must stay open until CreateProcessW returns —
        # they are closed by close_parent_ends(); a `with` block would
        # be wrong.
        self.stdin_f = open(os.devnull, "rb")  # noqa: SIM115
        self.nul_f = None
        self.h_stdin = _inheritable_handle(self.stdin_f.fileno())
        if capture_output:
            self.h_stdout = _inheritable_handle(self.w_out)
            self.h_stderr = _inheritable_handle(self.w_err)
        else:
            self.nul_f = open(os.devnull, "wb")  # noqa: SIM115
            self.h_stdout = self.h_stderr = _inheritable_handle(self.nul_f.fileno())

    def close_parent_ends(self):
        """Close the parent copies of the child ends once the process
        exists — keeping them open would break EOF detection."""
        for fd in (self.w_out, self.w_err):
            if fd is not None:
                os.close(fd)
        os.set_inheritable(self.stdin_f.fileno(), False)
        self.stdin_f.close()
        if self.nul_f is not None:
            self.nul_f.close()


def _sandbox_env_block(env, scratch):
    """Build the NUL-joined, alphabetically-sorted env block for the child."""
    child_env = dict(env) if env else {}
    child_env["TEMP"] = scratch
    child_env["TMP"] = scratch
    # AppContainer process init resolves the package-local appdata path
    # through LOCALAPPDATA — a custom env block without it makes
    # CreateProcessW fail with ERROR_ENVVAR_NOT_FOUND (203). Point it
    # at the scratch dir so tools keep a writable per-app location.
    child_env["LOCALAPPDATA"] = scratch
    # SystemRoot/windir are required by most child tooling; fill from
    # the parent when the sanitized env dropped them.
    for req in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH"):
        if req not in child_env and req in os.environ:
            child_env[req] = os.environ[req]
    return (
        "".join(f"{k}={v}\x00" for k, v in sorted(child_env.items(), key=lambda kv: kv[0].upper()))
        + "\x00"
    )


def _grant_sandbox_dirs(grant_dirs, sid_str):
    """Apply this container's extra ACL grants plus the
    ``TERMINAL_WINDOWS_SANDBOX_DIRS`` allowlist."""
    for path, write in grant_dirs:
        _grant_dir(path, write=write, sid_str=sid_str)
    for extra in os.environ.get("TERMINAL_WINDOWS_SANDBOX_DIRS", "").split(";"):
        extra = extra.strip()
        if extra:
            _grant_dir(extra, sid_str=sid_str)


def _startup_info(stdio):
    """STARTUPINFOEX with std handles pointing at the prepared pipes."""
    si = _STARTUPINFOEXW()
    # cb must cover the WHOLE STARTUPINFOEX (not just STARTUPINFO) when
    # lpAttributeList is used — otherwise CreateProcessW fails with
    # ERROR_INVALID_PARAMETER.
    si.StartupInfo.cb = ctypes.sizeof(si)
    si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
    si.StartupInfo.hStdInput = wintypes.HANDLE(stdio.h_stdin)
    si.StartupInfo.hStdOutput = wintypes.HANDLE(stdio.h_stdout)
    si.StartupInfo.hStdError = wintypes.HANDLE(stdio.h_stderr)
    return si


def _attribute_list(kernel32):
    """Allocate and initialize the proc-thread attribute list buffer."""
    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attr_buf = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(attr_buf, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return attr_buf


def _create_process(
    kernel32, attr_buf, si, sid, cap_psids, args, env_block, scratch, hidden_window
):
    """Attach SECURITY_CAPABILITIES, point ``si`` at the attribute list
    and CreateProcessW; returns ``_PROCESS_INFORMATION``.

    ``caps``/``sid_attrs`` must stay in THIS frame until CreateProcessW
    returns — the attribute list borrows the SID_AND_ATTRIBUTES array
    it points at, so a helper returning early would leave a dangling
    pointer for the kernel call.
    """
    # Capabilities travel as a SID_AND_ATTRIBUTES array; Attributes
    # is documented as unused/reserved-zero for capabilities.
    sid_attrs = None
    if cap_psids:
        sid_attrs = (_SID_AND_ATTRIBUTES * len(cap_psids))()
        for i, psid in enumerate(cap_psids):
            sid_attrs[i].Sid = psid.value
            sid_attrs[i].Attributes = 0
    caps = _SECURITY_CAPABILITIES(
        sid.value,
        ctypes.cast(sid_attrs, ctypes.c_void_p) if sid_attrs is not None else None,
        len(cap_psids),
        0,
    )
    if not kernel32.UpdateProcThreadAttribute(
        attr_buf,
        0,
        _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(caps),
        ctypes.sizeof(caps),
        None,
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # pylint: disable=attribute-defined-outside-init
    si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)

    cmdline = subprocess.list2cmdline(args)
    pi = _PROCESS_INFORMATION()
    creation_flags = (
        _EXTENDED_STARTUPINFO_PRESENT | _CREATE_UNICODE_ENVIRONMENT | _CREATE_NEW_PROCESS_GROUP
    )
    if hidden_window:
        creation_flags |= _CREATE_NO_WINDOW
    ok = kernel32.CreateProcessW(
        None,
        cmdline,
        None,
        None,
        True,
        creation_flags,
        env_block,
        scratch,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return pi


def _create_job_object(kernel32, h_process):
    """Wrap the child in a KILL_ON_JOB_CLOSE job; returns the job
    handle (or ``None`` when creation/setup failed — the child then
    runs without a job, as before)."""
    h_job = kernel32.CreateJobObjectW(None, None)
    if h_job:
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if kernel32.SetInformationJobObject(
            h_job,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            kernel32.AssignProcessToJobObject(h_job, h_process)
        else:
            kernel32.CloseHandle(h_job)
            h_job = None
    return h_job


def spawn_sandboxed(
    args,
    cwd=None,
    env=None,
    *,
    app_container_name=_APP_CONTAINER_NAME,
    capabilities=(),
    grant_dirs=(),
    hidden_window=True,
    job=True,
    capture_output=True,
):
    """Spawn ``args`` inside an AppContainer. Returns SandboxedProcess.

    Keyword arguments:

    - ``app_container_name``: stable AppContainer profile name. Each
      name maps to a distinct AppContainer SID, so filesystem grants
      are scoped to that sandbox only.
    - ``capabilities``: iterable of capability names placed into
      SECURITY_CAPABILITIES (e.g. ``privateNetworkClientServer`` for a
      process that must listen for inbound connections). The default
      empty list means NO network access for the child.
    - ``grant_dirs``: iterable of ``(path, writable)`` extra ACL grants
      for this container's SID (winvnc needs RX+write on its install
      dir for ``ultravnc.ini``/``WinVNC.log``).
    - ``hidden_window``: adds CREATE_NO_WINDOW for console children
      (terminal shells). Pass ``False`` for GUI children — the flag is
      a documented no-op for the Windows GUI subsystem, but keeping it
      out makes clear nothing constrains the child's interaction with
      the interactive window station (winvnc captures the desktop).
    - ``job``: wrap the child in a KILL_ON_JOB_CLOSE job object so
      terminate() kills the whole tree. Only valid while the returned
      object is kept alive — a caller that drops it and keeps just
      ``pid`` (the service manager kills via taskkill /PID) must pass
      ``False``, otherwise GC closing the job handle kills the child.
    - ``capture_output``: pipe the child's stdout/stderr back to the
      parent. Pass ``False`` for GUI children nobody reads — a full
      undrained pipe would block them.

    ``cwd`` is accepted for interface parity but intentionally ignored:
    the child always starts in its per-container scratch dir.

    Raises OSError/WinError on failure — the caller decides whether to
    fall back (auto) or propagate (strict).
    """
    if os.name != "nt":
        raise OSError("AppContainer sandbox is Windows-only")
    sid, sid_str = _get_sid(app_container_name)
    kernel32 = _proto()
    cap_psids = _capability_sids(capabilities)

    stdio = _SandboxStdio(capture_output)
    scratch = _scratch_dir(app_container_name)
    env_block = _sandbox_env_block(env, scratch)
    _grant_sandbox_dirs(grant_dirs, sid_str)

    si = _startup_info(stdio)
    attr_buf = _attribute_list(kernel32)
    try:
        pi = _create_process(
            kernel32, attr_buf, si, sid, cap_psids, args, env_block, scratch, hidden_window
        )
    finally:
        kernel32.DeleteProcThreadAttributeList(attr_buf)
        stdio.close_parent_ends()

    # Job object: kills the whole tree on terminate, matching the POSIX
    # process-group semantics the terminal relies on. Skipped when the
    # caller only keeps the PID — see the ``job`` parameter docs.
    h_job = _create_job_object(kernel32, pi.hProcess) if job else None

    kernel32.CloseHandle(pi.hThread)
    return SandboxedProcess(
        pi.dwProcessId,
        pi.hProcess,
        h_job,
        os.fdopen(stdio.r_out, "rb", buffering=0) if stdio.r_out is not None else None,
        os.fdopen(stdio.r_err, "rb", buffering=0) if stdio.r_err is not None else None,
    )


def sandbox_mode(env_var="TERMINAL_WINDOWS_SANDBOX"):
    """Return the sandbox mode configured by ``env_var``.

    ``auto`` falls back to an unsandboxed spawn when AppContainer
    setup fails — acceptable on development hosts, but under a
    hardened security profile (``public-hardened``/``private-overlay``)
    an unsandboxed child can read the service account's secrets, so
    ``auto`` is promoted to ``strict`` there. An explicit ``off`` is
    honoured regardless — the operator said so.
    """
    mode = os.environ.get(env_var, "auto").strip().lower()
    if mode not in ("auto", "strict", "off"):
        mode = "auto"
    if mode == "auto":
        try:
            from vnc_remote_secure.security.profiles import resolve_profile

            if resolve_profile() in ("public-hardened", "private-overlay"):
                return "strict"
        except Exception:  # noqa: BLE001 - profiles module optional
            pass
    return mode
