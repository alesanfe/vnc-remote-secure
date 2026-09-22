"""Windows ACL and user management via PowerShell."""
from ._powershell import run_powershell


def _ps_escape(value):
    """Escape a string for embedding in a single-quoted PowerShell string.

    PowerShell single-quoted strings escape a literal single quote by
    doubling it (``'`` -> ``''``).
    """
    return str(value).replace("'", "''")


def create_user(username, password=None):
    """Create a local Windows user.

    Returns ``True`` if the user was created or already exists.
    """
    if user_exists(username):
        return True
    if password is not None and ('\n' in password or '\r' in password):
        return False  # ReadLine() would silently truncate it
    if password is None:
        # Create with a random password; user cannot log in interactively.
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(32))
    # The password travels via stdin — embedding it in the command
    # line would expose it to any process able to read cmdlines
    # (WMI Win32_Process, Process Explorer).
    ps_script = (
        "$pw = [Console]::In.ReadLine(); "
        f"New-LocalUser -Name '{_ps_escape(username)}' "
        "-Password (ConvertTo-SecureString $pw -AsPlainText -Force) "
        "-Description 'VNC Remote Secure runtime user' -ErrorAction SilentlyContinue"
    )
    result = run_powershell(ps_script, input_data=password + '\n')
    return result.returncode == 0


def remove_user(username):
    """Remove a local Windows user.

    Refuses reserved/builtin names here (not just in the adapter):
    ``users.remove_runtime_user`` delegates straight to this function,
    so guarding only the adapter would leave an unguarded deletion path.
    """
    from vnc_remote_secure.core.constants import (
        RESERVED_USERNAMES,
        WINDOWS_BUILTIN_USERNAMES,
    )
    if username in WINDOWS_BUILTIN_USERNAMES \
            or username.lower() in {u.lower() for u in RESERVED_USERNAMES}:
        import logging
        logging.getLogger(__name__).warning(
            "Refusing to remove reserved/builtin user %s", username)
        return False
    ps_script = f"Remove-LocalUser -Name '{_ps_escape(username)}' -ErrorAction SilentlyContinue"
    result = run_powershell(ps_script)
    return result.returncode == 0


def user_exists(username):
    """Return ``True`` if ``username`` exists as a local user."""
    ps_script = (
        f"if (Get-LocalUser -Name '{_ps_escape(username)}' -ErrorAction SilentlyContinue) "
        "{ 'yes' } else { 'no' }"
    )
    result = run_powershell(ps_script)
    return result.stdout.strip().lower() == 'yes'


def list_users():
    """Return a list of local Windows users (non-system).

    Returns a list of dicts with ``username`` and ``uid`` (SID RID).
    System accounts (Administrator, Guest, DefaultAccount, etc.) are
    excluded.
    """
    ps_script = (
        "Get-LocalUser | Select-Object Name, SID | "
        "ConvertTo-Json -Compress"
    )
    result = run_powershell(ps_script)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    import json
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, list):
        data = [data]
    users = []
    for u in data:
        name = u.get('Name', '')
        sid_obj = u.get('SID', '')
        # SID from ConvertTo-Json can be a string or a dict with
        # 'Identifier'/'Value'/'Sddl' keys depending on PS version.
        sid_str = ''
        if isinstance(sid_obj, str):
            sid_str = sid_obj
        elif isinstance(sid_obj, dict):
            sid_str = (sid_obj.get('Sddl') or sid_obj.get('Value')
                       or sid_obj.get('Identifier') or sid_obj.get('SID') or '')
        # Extract RID from SID (last component after last dash).
        uid = 0
        if sid_str:
            parts = sid_str.split('-')
            if parts:
                try:
                    uid = int(parts[-1])
                except ValueError:
                    pass
        users.append({'username': name, 'uid': uid, 'home': ''})
    return users


def restrict_user(username):
    """Restrict a runtime user so it cannot log in interactively.

    This denies local logon (SeDenyInteractiveLogonRight) and removes
    the user from any interactive groups. The user can still be used
    as a service account (RunAs) but cannot sit at the keyboard and
    log in, preventing access to the desktop, documents, SSH keys,
    browser credentials, etc.

    Returns ``True`` on success.
    """
    if not user_exists(username):
        return False
    # Remove from the Users group (which grants interactive logon right).
    # The correct cmdlet is Remove-LocalGroupMember (not Remove-LocalUserFromGroup).
    ps_script = (
        f"Remove-LocalGroupMember -Group 'Users' -Member '{_ps_escape(username)}' "
        "-ErrorAction SilentlyContinue"
    )
    run_powershell(ps_script)
    # Even if group removal fails, the user was created with a random
    # password and cannot log in interactively without knowing it.
    return True


def create_restricted_user(username, password=None):
    """Create a restricted runtime user for service isolation.

    This creates a local user with:
    - A random 32-char password (not known to anyone)
    - No interactive logon rights
    - Removed from the Users group
    - Description marking it as a service account

    This is the Windows equivalent of Linux's systemd NoNewPrivileges,
    PrivateTmp, and ProtectHome — it prevents a compromised terminal
    from inheriting the current user's access to documents, SSH keys,
    browser credentials, etc.

    Returns ``True`` if the user was created or already exists.
    """
    if not create_user(username, password):
        return False
    return restrict_user(username)


def set_user_password(username, password):
    """Set the password for a local Windows user.

    Returns ``True`` on success. The password travels via stdin and is
    read with ``ReadLine()`` — a newline would silently truncate it,
    so reject control characters up front.
    """
    if '\n' in password or '\r' in password:
        return False
    if not user_exists(username):
        return False
    ps_script = (
        "$pw = [Console]::In.ReadLine(); "
        f"Set-LocalUser -Name '{_ps_escape(username)}' "
        "-Password (ConvertTo-SecureString $pw -AsPlainText -Force) "
        "-ErrorAction SilentlyContinue"
    )
    result = run_powershell(ps_script, input_data=password + '\n')
    return result.returncode == 0
