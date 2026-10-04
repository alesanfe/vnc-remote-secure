"""Linux system metrics collection."""

import logging
import subprocess

from vnc_remote_secure.core.processes import run_cmd

logger = logging.getLogger(__name__)


def get_os_display_name():
    """Return a human-readable OS name for Linux.

    Reads the ``PRETTY_NAME`` field from ``/etc/os-release`` if available.
    Returns ``None`` if the file is missing or cannot be parsed.
    """
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except FileNotFoundError:
        pass  # Not a Linux distribution with os-release; expected on minimal images.
    except (OSError, ValueError) as e:
        logger.warning("Linux os-release detection failed: %s", e, exc_info=True)
    return None


def get_system_metrics():
    """Return Linux system metrics (CPU load, memory, disk, uptime).

    All values are best-effort strings; ``'N/A'`` is used when a metric
    cannot be collected. Format matches the landing page expectations
    (percentages where applicable).
    """
    metrics = {
        "cpu": "N/A",
        "cpu_percent": "N/A",
        "memory": "N/A",
        "disk": "N/A",
        "uptime": "N/A",
    }
    metrics.update(_cpu_metrics())
    metrics.update(_memory_metrics())
    metrics.update(_disk_metrics())
    metrics.update(_uptime_metrics())
    return metrics


def _cpu_metrics() -> dict:
    """CPU load average (descriptive) + usage percentage."""
    metrics = {}
    try:
        with open("/proc/loadavg", encoding="utf-8") as f:
            load1 = f.readline().split()[0]
            metrics["cpu"] = f"Load: {load1}"
            metrics["cpu_fmt"] = {
                "key": "cpu_load", "params": {"load": load1}}
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        logger.warning("Linux loadavg detection failed: %s", e, exc_info=True)

    try:
        t1_total, t1_idle = _cpu_idle_sample()
        import time

        time.sleep(0.1)
        t2_total, t2_idle = _cpu_idle_sample()
        total_delta = t2_total - t1_total
        idle_delta = t2_idle - t1_idle
        if total_delta > 0:
            usage = (1 - idle_delta / total_delta) * 100
            metrics["cpu_percent"] = f"{usage:.0f}%"
            metrics["cpu_percent_fmt"] = {
                "key": "cpu_pct", "params": {"pct": f"{usage:.0f}"}}
    except FileNotFoundError:
        pass
    except (OSError, ValueError, ZeroDivisionError) as e:
        logger.warning("Linux CPU percent detection failed: %s", e, exc_info=True)
    return metrics


def _cpu_idle_sample() -> tuple:
    """Sample /proc/stat — returns (total_jiffies, idle_jiffies)."""
    with open("/proc/stat", encoding="utf-8") as f:
        line = f.readline()
    parts = line.split()
    # user, nice, system, idle, iowait, irq, softirq, steal, ...
    total = sum(int(p) for p in parts[1:])
    idle = int(parts[4]) + int(parts[5]) if len(parts) > 5 else int(parts[4])
    return total, idle


def _memory_metrics() -> dict:
    """Memory usage (with percentage)."""
    metrics = {}
    try:
        result = run_cmd(["free", "-m"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if line.startswith("Mem:"):
                parts = line.split()
                total = int(parts[1])
                used = int(parts[2])
                pct = (used / total) * 100 if total > 0 else 0
                metrics["memory"] = (
                    f"{pct:.0f}% ({used} MB / {total} MB)")
                metrics["memory_fmt"] = {
                    "key": "mem_usage",
                    "params": {
                        "pct": f"{pct:.0f}",
                        "used": used, "total": total}}
                break
    except FileNotFoundError:
        pass  # `free` not installed on minimal containers.
    except (subprocess.SubprocessError, ValueError, IndexError) as e:
        logger.warning("Linux memory detection failed: %s", e, exc_info=True)
    return metrics


def _disk_metrics() -> dict:
    """Disk usage for the root partition."""
    metrics = {}
    try:
        result = run_cmd(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) > 4:
                metrics["disk"] = (
                    f"/ {parts[1]} ({parts[2]} used, {parts[4]} full)")
                metrics["disk_fmt"] = {
                    "key": "disk_linux",
                    "params": {"size": parts[1], "used": parts[2],
                               "pct": parts[4]}}
    except FileNotFoundError:
        pass
    except (subprocess.SubprocessError, IndexError) as e:
        logger.warning("Linux disk detection failed: %s", e, exc_info=True)
    return metrics


def _uptime_metrics() -> dict:
    """System uptime formatted as ``Nh Nm``."""
    metrics = {}
    try:
        with open("/proc/uptime", encoding="utf-8") as f:
            uptime_seconds = float(f.readline().split()[0])
            hours = int(uptime_seconds // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            metrics["uptime"] = f"{hours}h {minutes}m"
            metrics["uptime_fmt"] = {
                "key": "uptime",
                "params": {"h": hours, "m": minutes}}
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        logger.warning("Linux uptime detection failed: %s", e, exc_info=True)
    return metrics
