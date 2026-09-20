"""Shared PowerShell execution helper for the Windows platform adapter."""
import subprocess


def run_powershell(script, input_data=None):
    """Run a PowerShell command and return the CompletedProcess.

    ``input_data`` is piped to the process's stdin — use it for
    secrets so they do not appear in the process command line, which
    any same-session process can read via WMI/Process Explorer.
    """
    return subprocess.run(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, text=True, timeout=60,
        input=input_data,
    )
