"""AppContainer process sandbox for the Windows web terminal.

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

The spawned shell gets a scratch working directory under %TEMP% that
is ACL-granted to the AppContainer SID, plus TEMP/TMP pointed at it so
tools still work. Extra directories can be exposed read-only via the
``TERMINAL_WINDOWS_SANDBOX_DIRS`` env var (semicolon-separated).

Mode is controlled by ``TERMINAL_WINDOWS_SANDBOX``:

- ``auto`` (default): sandbox; fall back to an unsandboxed spawn with a
  loud warning if CreateProcess fails (keeps the terminal usable on
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

_APP_CONTAINER_NAME = 'VncRemoteSecure.Terminal'
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

_appcontainer_sid = None          # PSID (c_void_p) — must stay alive
_appcontainer_sid_str = None
_granted_dirs: set = set()


class _SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ('AppContainerSid', ctypes.c_void_p),
        ('Capabilities', ctypes.c_void_p),
        ('CapabilityCount', wintypes.DWORD),
        ('Reserved', wintypes.DWORD),
    ]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR), ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.c_void_p), ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE), ('hStdError', wintypes.HANDLE),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ('StartupInfo', _STARTUPINFOW),
        ('lpAttributeList', ctypes.c_void_p),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.c_int64),
        ('PerJobUserTimeLimit', ctypes.c_int64),
        ('LimitFlags', wintypes.DWORD),
        ('MinimumWorkingSetSize', ctypes.c_size_t),
        ('MaximumWorkingSetSize', ctypes.c_size_t),
        ('ActiveProcessLimit', wintypes.DWORD),
        ('Affinity', ctypes.c_size_t),
        ('PriorityClass', wintypes.DWORD),
        ('SchedulingClass', wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation',
         _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ('IoInfo', ctypes.c_byte * 48),  # IO_COUNTERS — unused
        ('ProcessMemoryLimit', ctypes.c_size_t),
        ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t),
        ('PeakJobMemoryUsed', ctypes.c_size_t),
    ]


def _proto():
    """Declare ctypes prototypes — without them, 64-bit HANDLEs and.

    pointers passed positionally are truncated to c_int.
    """
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t)]
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
        ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
        ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
        ctypes.POINTER(_PROCESS_INFORMATION)]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p,
                                          wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE]
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE,
                                             wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE,
                                          wintypes.UINT]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE,
                                            wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32


def _get_sid():
    """Derive (once) the AppContainer SID for our stable profile name."""
    global _appcontainer_sid, _appcontainer_sid_str
    if _appcontainer_sid:
        return _appcontainer_sid
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    # The AppContainer profile/SID APIs live in userenv.dll (documented
    # host); some exports surface elsewhere depending on the build, so
    # probe a short list.
    host = None
    for dll in ('userenv', 'kernelbase', 'kernel32'):
        try:
            cand = ctypes.WinDLL(dll, use_last_error=True)
            if hasattr(cand, 'DeriveAppContainerSidFromAppContainerName'):
                host = cand
                break
        except (OSError, AttributeError):
            continue
    if host is None:
        for dll in ('userenv', 'kernelbase', 'kernel32'):
            try:
                cand = ctypes.WinDLL(dll, use_last_error=True)
                if hasattr(cand, 'CreateAppContainerProfile'):
                    host = cand
                    break
            except (OSError, AttributeError):
                continue
    if host is None:
        raise OSError("AppContainer APIs unavailable on this system")
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    sid = ctypes.c_void_p()
    try:
        derive = host.DeriveAppContainerSidFromAppContainerName
    except AttributeError:
        derive = None
    if derive:
        derive.argtypes = [wintypes.LPCWSTR,
                           ctypes.POINTER(ctypes.c_void_p)]
        derive.restype = ctypes.c_long
        hr = derive(_APP_CONTAINER_NAME, ctypes.byref(sid))
        if hr != 0:  # HRESULT S_OK == 0
            raise OSError(
                "DeriveAppContainerSidFromAppContainerName failed: "
                f"HRESULT {hr:#010x}")
    else:
        create = host.CreateAppContainerProfile
        create.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p)]
        create.restype = ctypes.c_long
        hr = create(_APP_CONTAINER_NAME, 'VNC Remote Secure Terminal',
                    'Sandboxed web-terminal commands', None, 0,
                    ctypes.byref(sid))
        if hr != 0:
            raise OSError(
                f"CreateAppContainerProfile failed: HRESULT {hr:#010x}")
    # String form for icacls grants.
    ptr = ctypes.c_void_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(ptr)):
        raise ctypes.WinError(ctypes.get_last_error())
    _appcontainer_sid_str = ctypes.wstring_at(ptr.value)
    kernel32.LocalFree(ptr)
    _appcontainer_sid = sid
    return sid


def _scratch_dir():
    """Create (once) the sandboxed working directory and ACL it."""
    path = os.path.join(tempfile.gettempdir(), 'vnc-term-sandbox')
    _grant_dir(path, write=True)
    return path


def _grant_dir(path, write=False):
    """Grant the AppContainer SID access to ``path`` via icacls.

    Everyone holds SeChangeNotifyPrivilege, so granting the leaf dir is
    enough — parents need not be readable.
    """
    real = os.path.realpath(path)
    key = (real, write)
    if key in _granted_dirs:
        return real
    sid = _appcontainer_sid_str or (_get_sid(), _appcontainer_sid_str)[1]
    rights = '(OI)(CI)(M)' if write else '(OI)(CI)(RX)'
    os.makedirs(real, exist_ok=True)
    from vnc_remote_secure.core.processes import run_cmd
    res = run_cmd(
        ['icacls', real, '/grant', f'*{sid}:{rights}'],
        capture_output=True, timeout=10)
    if res.returncode != 0:
        raise OSError(f"icacls grant on {real} failed: "
                      f"{res.stderr!r}")
    _granted_dirs.add(key)
    return real


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
            self._kernel32.GetExitCodeProcess(
                self._h_process, ctypes.byref(code))
            self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout=None):
        """Wait."""
        ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
        rc = self._kernel32.WaitForSingleObject(self._h_process, ms)
        if rc == _WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.pid, timeout)
        code = wintypes.DWORD()
        self._kernel32.GetExitCodeProcess(
            self._h_process, ctypes.byref(code))
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


def spawn_sandboxed(args, cwd=None, env=None):
    """Spawn ``args`` inside an AppContainer. Returns SandboxedProcess.

    Raises OSError/WinError on failure — the caller decides whether to
    fall back (auto) or propagate (strict).
    """
    if os.name != 'nt':
        raise OSError("AppContainer sandbox is Windows-only")
    sid = _get_sid()
    kernel32 = _proto()

    # stdio pipes — the child gets the write ends of stdout/stderr and
    # a NUL stdin. The std handles in STARTUPINFO reach the child even
    # with an attribute list present, so no HANDLE_LIST attribute is
    # needed (and adding one is rejected with ERROR_NOT_SUPPORTED).
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    # SIM115: the fd must stay open until CreateProcessW returns — it is
    # closed in the finally below; a `with` block would be wrong here.
    stdin_f = open(os.devnull, 'rb')  # noqa: SIM115
    h_stdin = _inheritable_handle(stdin_f.fileno())
    h_stdout = _inheritable_handle(w_out)
    h_stderr = _inheritable_handle(w_err)

    child_env = dict(env) if env else {}
    scratch = _scratch_dir()
    child_env['TEMP'] = scratch
    child_env['TMP'] = scratch
    # AppContainer process init resolves the package-local appdata path
    # through LOCALAPPDATA — a custom env block without it makes
    # CreateProcessW fail with ERROR_ENVVAR_NOT_FOUND (203). Point it
    # at the scratch dir so tools keep a writable per-app location.
    child_env['LOCALAPPDATA'] = scratch
    # SystemRoot/windir are required by most child tooling; fill from
    # the parent when the sanitized env dropped them.
    for req in ('SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH'):
        if req not in child_env and req in os.environ:
            child_env[req] = os.environ[req]
    for extra in os.environ.get(
            'TERMINAL_WINDOWS_SANDBOX_DIRS', '').split(';'):
        extra = extra.strip()
        if extra:
            _grant_dir(extra)

    env_block = ''.join(
        f'{k}={v}\x00'
        for k, v in sorted(child_env.items(), key=lambda kv: kv[0].upper())
    ) + '\x00'

    si = _STARTUPINFOEXW()
    # cb must cover the WHOLE STARTUPINFOEX (not just STARTUPINFO) when
    # lpAttributeList is used — otherwise CreateProcessW fails with
    # ERROR_INVALID_PARAMETER.
    si.StartupInfo.cb = ctypes.sizeof(si)
    si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
    si.StartupInfo.hStdInput = wintypes.HANDLE(h_stdin)
    si.StartupInfo.hStdOutput = wintypes.HANDLE(h_stdout)
    si.StartupInfo.hStdError = wintypes.HANDLE(h_stderr)

    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(
        None, 1, 0, ctypes.byref(size))
    attr_buf = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(
            attr_buf, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        caps = _SECURITY_CAPABILITIES(sid.value, None, 0, 0)
        if not kernel32.UpdateProcThreadAttribute(
                attr_buf, 0,
                _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(caps), ctypes.sizeof(caps), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        # pylint: disable=attribute-defined-outside-init
        si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)

        cmdline = subprocess.list2cmdline(args)
        pi = _PROCESS_INFORMATION()
        ok = kernel32.CreateProcessW(
            None, cmdline, None, None, True,
            (_EXTENDED_STARTUPINFO_PRESENT | _CREATE_NO_WINDOW
             | _CREATE_UNICODE_ENVIRONMENT | _CREATE_NEW_PROCESS_GROUP),
            env_block, scratch, ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.DeleteProcThreadAttributeList(attr_buf)
        # Parent copies of the child ends are closed once the process
        # exists — keeping them open would break EOF detection.
        for fd in (w_out, w_err):
            os.close(fd)
        os.set_inheritable(stdin_f.fileno(), False)
        stdin_f.close()

    # Job object: kills the whole tree on terminate, matching the POSIX
    # process-group semantics the terminal relies on.
    h_job = kernel32.CreateJobObjectW(None, None)
    if h_job:
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        if kernel32.SetInformationJobObject(
                h_job, _JobObjectExtendedLimitInformation,
                ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.AssignProcessToJobObject(h_job, pi.hProcess)
        else:
            kernel32.CloseHandle(h_job)
            h_job = None

    kernel32.CloseHandle(pi.hThread)
    return SandboxedProcess(
        pi.dwProcessId, pi.hProcess, h_job,
        os.fdopen(r_out, 'rb', buffering=0),
        os.fdopen(r_err, 'rb', buffering=0))


def sandbox_mode():
    """Return the configured Windows terminal sandbox mode."""
    mode = os.environ.get(
        'TERMINAL_WINDOWS_SANDBOX', 'auto').strip().lower()
    return mode if mode in ('auto', 'strict', 'off') else 'auto'
