"""Unit tests for the Windows installer UltraVNC provisioning.

These tests verify the discovery and provisioning logic in
``vnc_remote_secure.platform.windows.installer`` without performing
real network downloads or filesystem installs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'src'))

import vnc_remote_secure.core.paths as _paths
from vnc_remote_secure.platform.windows import installer


def _isolate_project_root(monkeypatch, tmp_path):
    """Point the project-bin fallback at an empty tmp dir so real
    checkout binaries (bin/ultravnc/<arch>/winvnc.exe) don't leak into
    the test."""
    monkeypatch.setattr(_paths, 'find_project_root',
                        lambda: str(tmp_path / 'no-bin-here'))

# ---------------------------------------------------------------------------
# _find_ultravnc
# ---------------------------------------------------------------------------


def test_find_ultravnc_returns_explicit_env_path(monkeypatch, tmp_path):
    """ULTRAVNC_PATH env var pointing to a real file is returned first."""
    fake_exe = tmp_path / 'winvnc.exe'
    fake_exe.write_text('fake')
    monkeypatch.setenv('ULTRAVNC_PATH', str(fake_exe))
    monkeypatch.setattr(installer.shutil, 'which', lambda name: None)
    assert installer._find_ultravnc() == str(fake_exe)


def test_find_ultravnc_returns_none_when_missing(monkeypatch, tmp_path):
    """Returns None when no env path, no install dir, and not on PATH."""
    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(tmp_path / 'missing'))
    monkeypatch.setattr(installer.shutil, 'which', lambda name: None)
    _isolate_project_root(monkeypatch, tmp_path)
    assert installer._find_ultravnc() is None


def test_find_ultravnc_falls_back_to_path(monkeypatch, tmp_path):
    """Falls back to PATH lookup when env and install dir are empty."""
    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(tmp_path / 'missing'))
    monkeypatch.setattr(installer.shutil, 'which',
                        lambda name: '/usr/bin/winvnc.exe' if name in ('winvnc.exe', 'winvnc') else None)
    _isolate_project_root(monkeypatch, tmp_path)
    assert installer._find_ultravnc() == '/usr/bin/winvnc.exe'


def test_find_ultravnc_finds_project_bin(monkeypatch, tmp_path):
    """Falls back to <project>/bin/ultravnc/<arch>/winvnc.exe (the
    download_dependencies.py target directory)."""
    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(tmp_path / 'missing'))
    monkeypatch.setattr(installer.shutil, 'which', lambda name: None)
    proj = tmp_path / 'proj'
    exe = proj / 'bin' / 'ultravnc' / 'x64' / 'winvnc.exe'
    exe.parent.mkdir(parents=True)
    exe.write_text('fake')
    monkeypatch.setattr(_paths, 'find_project_root', lambda: str(proj))
    assert installer._find_ultravnc() == str(exe)


def test_find_ultravnc_uses_install_dir(monkeypatch, tmp_path):
    """Returns winvnc.exe from the configured install directory."""
    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    install_dir = tmp_path / 'UltraVNC'
    install_dir.mkdir()
    (install_dir / 'winvnc.exe').write_text('fake')
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(install_dir))
    monkeypatch.setattr(installer.shutil, 'which', lambda name: None)
    assert installer._find_ultravnc() == str(install_dir / 'winvnc.exe')


# ---------------------------------------------------------------------------
# _ensure_ultravnc
# ---------------------------------------------------------------------------

def test_ensure_ultravnc_noop_when_present(monkeypatch, tmp_path):
    """Does nothing when UltraVNC is already available."""
    monkeypatch.setattr(installer, '_find_ultravnc',
                        lambda: str(tmp_path / 'winvnc.exe'))
    # If _ensure_ultravnc tries to download, urlopen will fail and raise.

    def _fail(*a, **k):
        raise AssertionError("should not download when UltraVNC present")
    monkeypatch.setattr(installer.urllib.request, 'urlopen', _fail)
    installer._ensure_ultravnc()
    assert not (tmp_path / 'UltraVNC').exists()


def test_ensure_ultravnc_downloads_and_extracts(monkeypatch, tmp_path):
    """Downloads a fake zip and extracts winvnc.exe to the install dir."""
    import io
    import zipfile

    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_find_ultravnc', lambda: None)

    install_dir = tmp_path / 'UltraVNC'
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(install_dir))

    # Build a fake zip containing winvnc.exe.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('winvnc.exe', 'fake-binary')
    zip_bytes = buf.getvalue()

    def _fake_urlopen(url, timeout=None):
        return io.BytesIO(zip_bytes)

    monkeypatch.setattr(installer.urllib.request, 'urlopen', _fake_urlopen)
    monkeypatch.setattr(installer.tempfile, 'TemporaryDirectory',
                        lambda: _TmpCtx(tmp_path))
    # The installer verifies the extracted binary's SHA-256 against the
    # manifest; the fake binary cannot match, so stub the verifier.
    monkeypatch.setattr(installer, '_verify_winvnc_hash', lambda p: True)

    installer._ensure_ultravnc()
    assert (install_dir / 'winvnc.exe').is_file()
    assert os.environ['ULTRAVNC_PATH'] == str(install_dir / 'winvnc.exe')


def test_ensure_ultravnc_removes_hash_mismatch(monkeypatch, tmp_path):
    """A binary whose SHA-256 mismatches the manifest is removed."""
    import io
    import zipfile

    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_find_ultravnc', lambda: None)
    install_dir = tmp_path / 'UltraVNC'
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(install_dir))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('winvnc.exe', 'tampered-binary')
    zip_bytes = buf.getvalue()

    def _fake_urlopen(url, timeout=None):
        return io.BytesIO(zip_bytes)

    monkeypatch.setattr(installer.urllib.request, 'urlopen', _fake_urlopen)
    monkeypatch.setattr(installer.tempfile, 'TemporaryDirectory',
                        lambda: _TmpCtx(tmp_path))
    # Real verifier: the fake binary will not match the manifest hash.
    monkeypatch.setattr(installer, '_verify_winvnc_hash', lambda p: False)

    installer._ensure_ultravnc()
    assert not (install_dir / 'winvnc.exe').is_file()
    assert 'ULTRAVNC_PATH' not in os.environ


def test_ensure_ultravnc_handles_download_failure(monkeypatch, tmp_path):
    """Logs a warning and does not raise when the download fails."""
    import urllib.error

    monkeypatch.delenv('ULTRAVNC_PATH', raising=False)
    monkeypatch.setattr(installer, '_find_ultravnc', lambda: None)
    monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(tmp_path / 'UltraVNC'))

    def _raise(url, timeout=None):
        raise urllib.error.URLError('boom')

    monkeypatch.setattr(installer.urllib.request, 'urlopen', _raise)
    monkeypatch.setattr(installer.tempfile, 'TemporaryDirectory',
                        lambda: _TmpCtx(tmp_path))
    # Should not raise and must not leave a half-installed binary or
    # ULTRAVNC_PATH pointing at a missing file.
    installer._ensure_ultravnc()
    assert 'ULTRAVNC_PATH' not in os.environ
    assert not (tmp_path / 'UltraVNC' / 'winvnc.exe').exists()


class _TmpCtx:
    """Minimal TemporaryDirectory replacement pointing at a real dir."""
    def __init__(self, path):
        self.name = str(path)

    def __enter__(self):
        return self.name

    def __exit__(self, *exc):
        return False


class TestEnsureUltravncSecurity:
    """Download/install guards — the archive is remote input."""

    def test_non_https_url_refused(self, monkeypatch):
        monkeypatch.setenv('ULTRAVNC_URL', 'http://evil.example/u.zip')
        assert installer._ensure_ultravnc() is None

    def test_file_scheme_refused(self, monkeypatch):
        monkeypatch.setenv('ULTRAVNC_URL', 'file:///etc/passwd')
        assert installer._ensure_ultravnc() is None

    def test_zip_slip_member_rejected(self, monkeypatch, tmp_path):
        """A member escaping the install dir must abort extraction."""
        import io
        import zipfile
        monkeypatch.setattr(installer, '_find_ultravnc', lambda: None)
        dest = tmp_path / 'ultravnc_dest'
        monkeypatch.setattr(installer, '_ULTRAVNC_INSTALL_DIR', str(dest))
        monkeypatch.setenv('ULTRAVNC_URL', 'https://x.example/u.zip')

        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, 'w') as zf:
            zf.writestr('../evil.exe', 'bad')
            zf.writestr('x64/winvnc.exe', 'ok')
        zip_bytes.seek(0)

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return zip_bytes.read()

        import urllib.request
        monkeypatch.setattr(urllib.request, 'urlopen',
                            lambda *a, **k: _Resp())
        dl = tmp_path / 'dl'
        dl.mkdir()
        monkeypatch.setattr(installer.tempfile, 'mkdtemp',
                            lambda *a, **k: str(dl))
        import pytest
        with pytest.raises(RuntimeError, match='Unsafe path'):
            installer._ensure_ultravnc()
        assert not (tmp_path / 'evil.exe').exists()
