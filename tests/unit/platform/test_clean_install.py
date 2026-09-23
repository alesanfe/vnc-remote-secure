"""Clean-install and idempotency tests for the Windows installer.

A second ``install()`` on an already-installed system must be a
no-op update — never regenerate certs, never wipe state, never
fail. The heavy OS steps (elevation, service registration, user
creation) are mocked; the idempotency logic itself runs for real.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest  # noqa: E402

from vnc_remote_secure.platform.windows import installer  # noqa: E402


def _isolate_install(monkeypatch, tmp_path):
    """Redirect every install side-effect into tmp_path."""
    monkeypatch.setattr(installer, '_is_elevated', lambda: True)
    monkeypatch.setenv('ProgramData', str(tmp_path / 'ProgramData'))
    monkeypatch.setenv('PUBLIC_BIND_HOST', '127.0.0.1')
    # Paths under the fake install root.
    from vnc_remote_secure.core import paths
    monkeypatch.setattr(paths, 'get_config_dir',
                        lambda: str(tmp_path / 'cfg'))
    monkeypatch.setattr(paths, 'get_data_dir',
                        lambda: str(tmp_path / 'data'))
    monkeypatch.setattr(paths, 'get_log_dir',
                        lambda: str(tmp_path / 'log'))
    monkeypatch.setattr(paths, 'get_run_dir',
                        lambda: str(tmp_path / 'run'))
    monkeypatch.setattr(paths, 'get_ssl_dir',
                        lambda: str(tmp_path / 'ssl'))
    # The installer resolves paths through its own imports.
    monkeypatch.setattr(installer, 'get_ssl_dir',
                        lambda: str(tmp_path / 'ssl'), raising=False)
    # UltraVNC already provisioned -> _ensure_ultravnc no-ops.
    monkeypatch.setattr(installer, '_find_ultravnc',
                        lambda: str(tmp_path / 'winvnc.exe'))
    calls = {'cert': 0, 'user': 0, 'service': 0}
    monkeypatch.setattr(
        installer, 'generate_self_signed',
        lambda c, k: (calls.__setitem__('cert', calls['cert'] + 1),
                      open(c, 'w').write('cert'),
                      open(k, 'w').write('key')))
    monkeypatch.setattr(installer, '_create_temp_user',
                        lambda: calls.__setitem__('user',
                                                  calls['user'] + 1))
    try:
        import vnc_remote_secure.platform.windows.services as ws
        monkeypatch.setattr(ws, 'install_service',
                            lambda n: calls.__setitem__(
                                'service', calls['service'] + 1))
    except ImportError:
        pass
    return calls


def test_clean_install_creates_layout(monkeypatch, tmp_path):
    """A fresh install produces the standard directory layout,
    certs, and registers the service."""
    calls = _isolate_install(monkeypatch, tmp_path)
    assert installer.install() is True
    assert (tmp_path / 'ssl' / 'fullchain.pem').exists()
    assert calls['cert'] == 1
    assert calls['service'] == 1
    # Package copied under the fake ProgramData.
    assert (tmp_path / 'ProgramData' / 'VncRemoteSecure' / 'src'
            / 'vnc_remote_secure').is_dir()


def test_second_install_is_idempotent(monkeypatch, tmp_path):
    """Re-running install must NOT regenerate the certificate or
    fail — an upgrade-style reinstall preserves operator state."""
    calls = _isolate_install(monkeypatch, tmp_path)
    assert installer.install() is True
    cert = tmp_path / 'ssl' / 'fullchain.pem'
    first = cert.read_bytes()
    assert installer.install() is True
    assert cert.read_bytes() == first
    assert calls['cert'] == 1  # still one generation, not two
    assert calls['service'] == 2  # service re-registration is safe


def test_install_requires_elevation(monkeypatch, tmp_path):
    """A non-elevated install fails fast — half-installing under
    ProgramData leaves a worse state than refusing."""
    _isolate_install(monkeypatch, tmp_path)
    monkeypatch.setattr(installer, '_is_elevated', lambda: False)
    with pytest.raises(PermissionError):
        installer.install()
    # The dir exists (conftest) but no certificate was generated —
    # a refused install leaves no half-written state.
    assert not (tmp_path / 'ssl' / 'fullchain.pem').exists()
    assert not (tmp_path / 'ProgramData' / 'VncRemoteSecure').exists()


def test_public_bind_opens_only_gateway_port(monkeypatch, tmp_path):
    """Only the landing port gets a firewall rule — opening backends
    would expose them if an operator later binds 0.0.0.0."""
    _isolate_install(monkeypatch, tmp_path)
    monkeypatch.setenv('PUBLIC_BIND_HOST', '0.0.0.0')
    monkeypatch.setenv('LANDING_PORT', '8000')
    opened = []
    monkeypatch.setattr(installer, 'configure_firewall',
                        lambda port, proto: opened.append((port, proto)),
                        raising=False)
    installer.install()
    assert opened == [(8000, 'tcp')]


def test_loopback_install_opens_no_firewall(monkeypatch, tmp_path):
    _isolate_install(monkeypatch, tmp_path)
    opened = []
    monkeypatch.setattr(installer, 'configure_firewall',
                        lambda port, proto: opened.append(port),
                        raising=False)
    installer.install()
    assert opened == []
