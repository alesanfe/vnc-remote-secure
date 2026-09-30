"""Browser-E2E hygiene: reclaim orphaned Playwright drivers.

An aborted run (Ctrl+C, pytest-timeout, CI kill) leaves the
playwright-driver ``node.exe`` and its headless chrome children
behind; on Windows those orphans keep the driver's pipe half-open
and make the NEXT run's ``sync_playwright()`` hang inside the
driver channel — we hit exactly that while running the portal spec.

At session start (before any fixture launches a browser) sweep
processes whose command line identifies them as a playwright
driver/browser spawn. Scoped tightly so unrelated node processes
are never touched:

* ``node.exe`` whose command line contains ``playwright[\\/]driver``
* any process whose executable path lives under ``ms-playwright``
  (the browser cache — headless chrome, ffmpeg)

A legitimately-running parallel browser test also matches — this
suite is not meant to run concurrently with itself on one machine,
which is precisely the failure mode we are defending against.
"""
import os
import re
import subprocess

import pytest

_DRIVER_RE = re.compile(r'playwright[\\/]driver', re.IGNORECASE)
_BROWSER_RE = re.compile(r'ms-playwright', re.IGNORECASE)
_BROWSER_EXE = ('headless_shell', 'chrome', 'chromium', 'ffmpeg',
                'msedge', 'firefox')


def _processes() -> list:
    """(pid, name, cmdline-or-exepath) tuples — psutil if present,
    else WMI. Empty list when neither is available (POSIX fallback
    uses ps via /proc)."""
    try:
        import psutil  # type: ignore
        out = []
        for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
            try:
                cmd = ' '.join(p.info.get('cmdline') or [])
                exe = p.info.get('exe') or ''
                out.append((p.info['pid'], p.info['name'] or '',
                            cmd + ' ' + exe))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return out
    except ImportError:
        pass
    if os.name == 'nt':
        try:
            out = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 "Get-CimInstance Win32_Process | "
                 "ForEach-Object { \"$($_.ProcessId)|$($_.Name)|"
                 "$($_.CommandLine)\" }"],
                capture_output=True, text=True, timeout=30)
            rows = []
            for ln in out.stdout.splitlines():
                parts = ln.split('|', 2)
                if len(parts) == 3 and parts[0].isdigit():
                    rows.append((int(parts[0]), parts[1], parts[2]))
            return rows
        except (OSError, subprocess.SubprocessError):
            return []
    # POSIX: /proc scan.
    rows = []
    proc = '/proc'
    if os.path.isdir(proc):
        for name in os.listdir(proc):
            if not name.isdigit():
                continue
            try:
                with open(os.path.join(proc, name, 'cmdline'),
                          'rb') as f:
                    cmd = f.read().replace(b'\x00', b' ').decode(
                        errors='replace')
                # POSIX /proc gives no exe name column — derive it
                # from argv[0]'s basename so the driver check's
                # 'node' match works here too (previously name=''
                # made is_driver impossible on POSIX).
                argv0 = cmd.strip().split(' ', 1)[0]
                proc_name = os.path.basename(argv0) if argv0 else ''
                rows.append((int(name), proc_name, cmd))
            except OSError:
                continue
    return rows


def _kill(pid: int) -> None:
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(pid)],
                           capture_output=True, timeout=10)
        else:
            os.kill(pid, 9)
    except (OSError, subprocess.SubprocessError):
        pass


def _sweep_orphan_drivers() -> int:
    """Kill playwright-driver/browser orphans; returns the count."""
    me = os.getpid()
    killed = 0
    for pid, name, cmd in _processes():
        if pid == me:
            continue
        cmd = cmd or ''
        lname = name.lower()
        is_driver = _DRIVER_RE.search(cmd) and 'node' in lname
        # The browser-cache match is scoped to actual browser-ish
        # executables — a bare 'ms-playwright' substring in the
        # cmdline could belong to another project's own playwright
        # run (shared cache dir), which we must not reap.
        is_browser_child = _BROWSER_RE.search(cmd) and any(
            exe in lname for exe in _BROWSER_EXE)
        if is_driver or is_browser_child:
            _kill(pid)
            killed += 1
    return killed


@pytest.fixture(scope='session', autouse=True)
def clean_orphan_playwright_drivers():
    """Once per browser-e2e session: sweep leftover drivers so a
    previous aborted run cannot hang this one inside the driver's
    sync channel."""
    killed = _sweep_orphan_drivers()
    if killed:
        print(f'\n[browser-e2e] killed {killed} orphaned playwright '
              'process(es) from a previous run')
    yield
    # Post-run sweep: a test killed mid-flight leaves the same mess.
    _sweep_orphan_drivers()
