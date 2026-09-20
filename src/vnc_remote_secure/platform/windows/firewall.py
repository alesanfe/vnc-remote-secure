"""Windows Firewall management via PowerShell NetFirewall cmdlets."""
from vnc_remote_secure.platform.windows.permissions import _ps_escape

from ._powershell import run_powershell


def configure_firewall(port, protocol='tcp'):
    """Create an inbound Windows Firewall allow rule for ``port``.

    Returns ``True`` on success.
    """
    port = int(port)
    protocol = 'TCP' if str(protocol).lower() == 'tcp' else 'UDP'
    rule_name = _ps_escape(f'VncRemoteSecure-{port}-{protocol.lower()}')
    ps_script = (
        f"New-NetFirewallRule -DisplayName '{rule_name}' "
        f"-Direction Inbound -Protocol {protocol} "
        f"-LocalPort {port} -Action Allow -Profile Private,Domain "
        f"-ErrorAction SilentlyContinue"
    )
    result = run_powershell(ps_script)
    return result.returncode == 0


def remove_firewall_rule(name):
    """Remove a Windows Firewall rule by display name (supports wildcards)."""
    ps_script = (
        f"Remove-NetFirewallRule -DisplayName '{_ps_escape(name)}*' "
        "-ErrorAction SilentlyContinue"
    )
    result = run_powershell(ps_script)
    return result.returncode == 0


def list_firewall_rules():
    """Return a list of VNC Remote Secure firewall rule display names."""
    ps_script = (
        "Get-NetFirewallRule -DisplayName 'VncRemoteSecure*' "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
    )
    result = run_powershell(ps_script)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def verify_firewall_rules(ports):
    """Verify that firewall rules exist for each port in ``ports``.

    Args:
        ports: Iterable of ``(port, protocol)`` tuples.

    Returns:
        A dict mapping ``(port, protocol)`` to a boolean indicating
        whether the rule exists.
    """
    existing = set(list_firewall_rules())
    result = {}
    for port, protocol in ports:
        rule_name = f'VncRemoteSecure-{port}-{protocol}'
        result[(port, protocol)] = rule_name in existing
    return result
