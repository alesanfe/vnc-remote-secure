"""Windows system metrics collection."""
import logging
import re
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)


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
    try:
        result = subprocess.run(
            ['wmic', 'cpu', 'get', 'loadpercentage', '/value'],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r'LoadPercentage=(\d+)', result.stdout)
        if match:
            pct = match.group(1)
            metrics['cpu'] = f"{pct}%"
            metrics['cpu_percent'] = f"{pct}%"
    except Exception as e:
        logger.debug("Windows CPU load detection failed: %s", e)

    # Memory usage (with percentage)
    try:
        result = subprocess.run(
            ['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/value'],
            capture_output=True, text=True, timeout=5,
        )
        total_match = re.search(r'TotalVisibleMemorySize=(\d+)', result.stdout)
        free_match = re.search(r'FreePhysicalMemory=(\d+)', result.stdout)
        if total_match and free_match:
            total_kb = int(total_match.group(1))
            free_kb = int(free_match.group(1))
            used_kb = total_kb - free_kb
            pct = (used_kb / total_kb) * 100 if total_kb > 0 else 0
            metrics['memory'] = f"{pct:.0f}% ({used_kb // 1024} MB / {total_kb // 1024} MB)"
    except Exception as e:
        logger.debug("Windows memory detection failed: %s", e)

    # Disk usage (first logical disk)
    try:
        result = subprocess.run(
            ['wmic', 'logicaldisk', 'get', 'size,freespace,caption', '/value'],
            capture_output=True, text=True, timeout=5,
        )
        current = {}
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                key, val = key.strip(), val.strip()
                if key == 'Caption':
                    if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
                        size_gb = int(current['Size']) / (1024**3)
                        free_gb = int(current['FreeSpace']) / (1024**3)
                        pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
                        if metrics['disk'] == 'N/A':
                            metrics['disk'] = f"{current['Caption']} {pct:.0f}% ({free_gb:.0f} GB free)"
                    current = {'Caption': val}
                elif key == 'Size':
                    try:
                        current['Size'] = int(val)
                    except ValueError:
                        logger.debug("Disk Size parse failed for value %r", val)
                elif key == 'FreeSpace':
                    try:
                        current['FreeSpace'] = int(val)
                    except ValueError:
                        logger.debug("Disk FreeSpace parse failed for value %r", val)
        if current.get('Caption') and current.get('Size') and current.get('FreeSpace'):
            size_gb = int(current['Size']) / (1024**3)
            free_gb = int(current['FreeSpace']) / (1024**3)
            pct = ((size_gb - free_gb) / size_gb) * 100 if size_gb > 0 else 0
            if metrics['disk'] == 'N/A':
                metrics['disk'] = f"{current['Caption']} {pct:.0f}% ({free_gb:.0f} GB free)"
    except Exception as e:
        logger.debug("Windows disk detection failed: %s", e)

    # Uptime from LastBootUpTime
    try:
        result = subprocess.run(
            ['wmic', 'os', 'get', 'LastBootUpTime', '/value'],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r'LastBootUpTime=(.+)', result.stdout)
        if match:
            boot_str = match.group(1).strip()
            if '.' in boot_str:
                boot_dt = datetime.strptime(boot_str.split('.')[0], '%Y%m%d%H%M%S')
                delta = datetime.now() - boot_dt
                hours = int(delta.total_seconds() // 3600)
                minutes = int((delta.total_seconds() % 3600) // 60)
                metrics['uptime'] = f"{hours}h {minutes}m"
    except Exception as e:
        logger.debug("Windows uptime detection failed: %s", e)

    return metrics
