"""Windows system metrics collection.

Uses PowerShell ``Get-CimInstance`` (the supported replacement for the
deprecated ``wmic``) to collect CPU load, memory, disk, and uptime.
"""
import logging
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)


def _run_ps(command):
    """Run a PowerShell command and return its stdout (or None on failure)."""
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', command],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        # PowerShell not available (e.g. non-Windows test host or stripped image).
        return None
    except subprocess.SubprocessError as e:
        logger.warning("PowerShell command failed (%s): %s", command, e, exc_info=True)
        return None


def get_os_display_name():
    """Return a human-readable OS name (e.g. 'Windows 11', 'Windows 10').

    ``platform.release()`` returns '10' on Windows 11, so we query the
    WMI caption via PowerShell's ``Get-CimInstance`` (the supported
    replacement for the deprecated ``wmic``).
    """
    caption = _run_ps("(Get-CimInstance Win32_OperatingSystem).Caption")
    if caption:
        if 'Windows 11' in caption:
            return 'Windows 11'
        if 'Windows 10' in caption:
            return 'Windows 10'
        return caption
    return None


def get_system_metrics():
    """Return Windows system metrics (CPU load, memory, disk, uptime).

    All values are best-effort strings; ``'N/A'`` is used when a metric
    cannot be collected. Format matches the landing page expectations
    (percentages where applicable).
    """
    metrics = {
        'cpu': 'N/A',
        'cpu_percent': 'N/A',
        'memory': 'N/A',
        'disk': 'N/A',
        'uptime': 'N/A',
    }

    # CPU load percentage
    pct = _run_ps(
        "(Get-CimInstance Win32_Processor).LoadPercentage"
    )
    if pct and pct.isdigit():
        metrics['cpu'] = f"{pct}%"
        metrics['cpu_percent'] = f"{pct}%"

    # Memory usage (with percentage)
    mem = _run_ps(
        "$o = Get-CimInstance Win32_OperatingSystem; "
        "$total = [math]::Round($o.TotalVisibleMemorySize/1024,0); "
        "$free = [math]::Round($o.FreePhysicalMemory/1024,0); "
        "$used = $total - $free; "
        "$pct = [math]::Round(($used/$total)*100,0); "
        "$pct.ToString() + '|' + $used.ToString() + '|' + $total.ToString()"
    )
    if mem and '|' in mem:
        parts = mem.split('|')
        if len(parts) == 3:
            pct_m, used_mb, total_mb = parts
            metrics['memory'] = f"{pct_m}% ({used_mb} MB / {total_mb} MB)"

    # Disk usage (first logical disk)
    disk = _run_ps(
        "$d = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
        "Select-Object -First 1; "
        "$size = [math]::Round($d.Size/1GB,0); "
        "$free = [math]::Round($d.FreeSpace/1GB,0); "
        "$pct = [math]::Round((($size-$free)/$size)*100,0); "
        "$d.DeviceID + '|' + $pct.ToString() + '|' + $free.ToString()"
    )
    if disk and '|' in disk:
        parts = disk.split('|')
        if len(parts) == 3:
            drive, pct_d, free_gb = parts
            metrics['disk'] = f"{drive} {pct_d}% ({free_gb} GB free)"

    # Uptime from LastBootUpTime
    boot = _run_ps(
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"
    )
    if boot:
        try:
            boot_dt = datetime.fromisoformat(boot)
            delta = datetime.now(boot_dt.tzinfo) - boot_dt
            hours = int(delta.total_seconds() // 3600)
            minutes = int((delta.total_seconds() % 3600) // 60)
            metrics['uptime'] = f"{hours}h {minutes}m"
        except (ValueError, TypeError) as e:
            logger.debug("Windows uptime parse failed: %s", e)

    return metrics
