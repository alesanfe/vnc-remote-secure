"""Unit tests for certificates.py and tls_validation.py.

Covers the branches not exercised by the existing TLS tests:
- generate_self_signed via the cryptography backend (real cert+key
  pair on disk, then round-tripped through _validate_certificate)
- create_ssl_context's hardened-profile fail-closed behavior
- request_letsencrypt domain validation + plugin fallback
- validate_tls_config's cipher/cert/env checks
- get_recommended_ssl_context policy flags
"""

import os
import ssl
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.security import certificates, tls_validation  # noqa: E402

# ---------------------------------------------------------------------------
# generate_self_signed (cryptography backend)
# ---------------------------------------------------------------------------


def test_generate_self_signed_creates_valid_pair(tmp_path, monkeypatch):
    """The cryptography backend writes a cert+key pair that
    _validate_certificate accepts and that loads into an SSLContext."""
    pytest.importorskip("cryptography")
    cert = str(tmp_path / "fullchain.pem")
    key = str(tmp_path / "privkey.pem")
    # Keep key ACL/chmod portable on Windows CI.
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    assert certificates.generate_self_signed(cert, key) is True
    assert os.path.exists(cert)
    assert os.path.exists(key)

    # Round-trip: certificate validates clean (key size, expiry,
    # cert/key pair match).
    findings = tls_validation._validate_certificate(cert, key)
    assert findings == []

    # And it loads into a real TLS context.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)


def test_generate_self_signed_default_cn_has_localhost_san(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from cryptography import x509

    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    certificates.generate_self_signed(cert, key)
    loaded = x509.load_pem_x509_certificate(open(cert, "rb").read())
    san = loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = san.get_values_for_type(x509.DNSName)
    assert "localhost" in names


def test_generate_self_signed_missing_dir_created(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    deep = tmp_path / "a" / "b" / "c.pem"
    key = tmp_path / "a" / "b" / "k.pem"
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    assert certificates.generate_self_signed(str(deep), str(key)) is True


# ---------------------------------------------------------------------------
# create_ssl_context — profile fail-open/fail-closed
# ---------------------------------------------------------------------------


def test_create_ssl_context_disabled_by_tls_enabled(monkeypatch):
    monkeypatch.setenv("TLS_ENABLED", "false")
    assert certificates.create_ssl_context() is None


def test_create_ssl_context_disabled_by_disable_ssl(monkeypatch):
    monkeypatch.setenv("DISABLE_SSL", "true")
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    assert certificates.create_ssl_context() is None


def test_create_ssl_context_no_cert_returns_none(monkeypatch, tmp_path):
    monkeypatch.delenv("SSL_CERT", raising=False)
    monkeypatch.delenv("SSL_KEY", raising=False)
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    # Ensure the ssl-dir discovery finds nothing.
    monkeypatch.setenv("VNC_REMOTE_PROFILE", "development")
    import vnc_remote_secure.core.paths as paths_mod

    monkeypatch.setattr(paths_mod, "get_ssl_dir", lambda: str(tmp_path / "empty"))
    monkeypatch.setattr(paths_mod, "find_project_root", lambda: str(tmp_path / "emptyroot"))
    assert certificates.create_ssl_context() is None


def test_create_ssl_context_missing_cert_hardened_aborts(monkeypatch, tmp_path):
    """Configured-but-missing cert under a hardened profile raises —
    silently falling back to HTTP would downgrade the deployment."""
    monkeypatch.setenv("SSL_CERT", str(tmp_path / "gone.pem"))
    monkeypatch.setenv("SSL_KEY", str(tmp_path / "gone.key"))
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    monkeypatch.setenv("VNC_REMOTE_PROFILE", "public-hardened")
    with pytest.raises(RuntimeError, match="SSL cert/key"):
        certificates.create_ssl_context()


def test_create_ssl_context_missing_cert_dev_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("SSL_CERT", str(tmp_path / "gone.pem"))
    monkeypatch.setenv("SSL_KEY", str(tmp_path / "gone.key"))
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    monkeypatch.setenv("VNC_REMOTE_PROFILE", "development")
    assert certificates.create_ssl_context() is None


def test_create_ssl_context_loads_real_cert(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    certificates.generate_self_signed(cert, key)
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    monkeypatch.setenv("VNC_REMOTE_PROFILE", "development")
    ctx = certificates.create_ssl_context(cert, key)
    assert ctx is not None
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_create_ssl_context_bad_cert_hardened_aborts(tmp_path, monkeypatch):
    """A corrupt cert under a hardened profile raises — not warn+HTTP."""
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    cert.write_text("not a pem")
    key.write_text("not a key")
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.delenv("TLS_ENABLED", raising=False)
    monkeypatch.setenv("VNC_REMOTE_PROFILE", "trusted-lan")
    with pytest.raises(RuntimeError, match="SSL context failed"):
        certificates.create_ssl_context(str(cert), str(key))


# ---------------------------------------------------------------------------
# request_letsencrypt
# ---------------------------------------------------------------------------


def test_letsencrypt_rejects_traversal_domain(monkeypatch):
    """'../..' in a domain must not escape the letsencrypt live dir."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/certbot")
    assert certificates.request_letsencrypt("../../etc/passwd", "a@b.c") is False
    assert certificates.request_letsencrypt("evil.com;rm -rf /", "a@b.c") is False


def test_letsencrypt_rejects_missing_args(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/certbot")
    assert certificates.request_letsencrypt("", "a@b.c") is False
    assert certificates.request_letsencrypt("d.com", "") is False


def test_letsencrypt_no_certbot_returns_false(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda x: None)
    assert certificates.request_letsencrypt("d.com", "a@b.c") is False


def test_letsencrypt_falls_back_to_standalone(monkeypatch, tmp_path):
    """nginx plugin failure falls through to --standalone."""
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode = rc
            self.stderr = ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if "--standalone" in cmd:
            return R(0)
        return R(1)

    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/certbot")
    monkeypatch.setattr(certificates, "run_cmd", fake_run)
    # The certs must exist under /etc/letsencrypt/live/<domain> —
    # patch the filesystem checks.
    live = tmp_path / "live"
    domain_dir = live / "d.com"
    domain_dir.mkdir(parents=True)
    (domain_dir / "fullchain.pem").write_text("c")
    (domain_dir / "privkey.pem").write_text("k")
    monkeypatch.setattr(os.path, "join", os.path.join)  # keep real join
    monkeypatch.setattr(
        certificates.os.path, "exists", lambda p: str(p).startswith(str(live)) or os.path.exists(p)
    )
    # Redirect /etc/letsencrypt to tmp
    real_join = os.path.join
    monkeypatch.setattr(
        certificates.os.path,
        "join",
        lambda *a: (
            real_join(str(live), *a[2:])
            if len(a) > 1 and a[0] == "/etc/letsencrypt/live"
            else real_join(*a)
        ),
    )
    assert certificates.request_letsencrypt("d.com", "a@b.c") is True
    assert any("--nginx" in c for c in calls)
    assert any("--standalone" in c for c in calls)


# ---------------------------------------------------------------------------
# validate_tls_config
# ---------------------------------------------------------------------------


def test_validate_tls_disabled_returns_info(monkeypatch):
    monkeypatch.setattr("vnc_remote_secure.security.profiles._is_tls_enabled", lambda: False)
    findings = tls_validation.validate_tls_config()
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_validate_tls_weak_cipher_flagged(monkeypatch):
    monkeypatch.setattr("vnc_remote_secure.security.profiles._is_tls_enabled", lambda: True)
    monkeypatch.setenv("SSL_CIPHERS", "RC4-MD5")
    monkeypatch.delenv("SSL_CERT", raising=False)
    monkeypatch.delenv("SSL_KEY", raising=False)
    findings = tls_validation.validate_tls_config()
    assert any(f["severity"] == "critical" and "RC4" in f["message"] for f in findings)


def test_validate_tls_strong_ciphers_not_flagged(monkeypatch):
    monkeypatch.setattr("vnc_remote_secure.security.profiles._is_tls_enabled", lambda: True)
    monkeypatch.setenv("SSL_CIPHERS", "ECDHE+AESGCM:ECDHE+CHACHA20")
    monkeypatch.delenv("SSL_CERT", raising=False)
    monkeypatch.delenv("SSL_KEY", raising=False)
    findings = tls_validation.validate_tls_config()
    assert not any(f["severity"] == "critical" for f in findings)


def test_validate_tls_cert_without_key_warns(monkeypatch, tmp_path):
    monkeypatch.setattr("vnc_remote_secure.security.profiles._is_tls_enabled", lambda: True)
    cert = tmp_path / "only.pem"
    cert.write_text("x")
    monkeypatch.setenv("SSL_CERT", str(cert))
    monkeypatch.delenv("SSL_KEY", raising=False)
    monkeypatch.delenv("SSL_CIPHERS", raising=False)
    findings = tls_validation.validate_tls_config()
    assert any("SSL_KEY" in f["message"] for f in findings)


# ---------------------------------------------------------------------------
# get_recommended_ssl_context
# ---------------------------------------------------------------------------


def test_recommended_context_policy():
    ctx = tls_validation.get_recommended_ssl_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_COMPRESSION
    # OP_SINGLE_DH_USE is 0 (a no-op constant) on OpenSSL 3.x builds —
    # only assert it when the platform actually defines a non-zero flag.
    if ssl.OP_SINGLE_DH_USE:
        assert ctx.options & ssl.OP_SINGLE_DH_USE
    assert ctx.options & ssl.OP_NO_RENEGOTIATION


# ---------------------------------------------------------------------------
# _validate_certificate — real generated certs
# ---------------------------------------------------------------------------


def test_validate_certificate_expired_flagged(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    # days_valid=0 → already expired
    certificates.generate_self_signed(cert, key, days_valid=0)
    import time

    time.sleep(1.1)  # let the not_after tick past now
    findings = tls_validation._validate_certificate(cert, key)
    assert any(
        "expired" in f["message"].lower() or "expires" in f["message"].lower() for f in findings
    )


def test_validate_certificate_mismatched_key(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    cert2 = str(tmp_path / "c2.pem")
    key2 = str(tmp_path / "k2.pem")
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    certificates.generate_self_signed(cert, key)
    certificates.generate_self_signed(cert2, key2)
    # cert1 with key2 — public numbers differ.
    findings = tls_validation._validate_certificate(cert, key2)
    assert any("do not match" in f["message"] for f in findings)


# ---------------------------------------------------------------------------
# _generate_via_openssl fallback + CN sanitisation
# ---------------------------------------------------------------------------


def _no_cryptography(monkeypatch):
    """Force the cryptography import in generate_self_signed to fail so
    the openssl CLI fallback runs."""
    monkeypatch.setitem(sys.modules, "cryptography", None)


def test_openssl_fallback_invoked_when_cryptography_missing(tmp_path, monkeypatch):
    _no_cryptography(monkeypatch)
    calls = []
    import types

    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda cmd, **kw: calls.append(cmd) or types.SimpleNamespace(returncode=0, stderr=""),
    )
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    assert certificates.generate_self_signed(cert, key, common_name="my.host") is True
    assert calls and calls[0][:2] == ["openssl", "req"]
    subj = calls[0][calls[0].index("-subj") + 1]
    assert subj == "/CN=my.host"


def test_openssl_cn_strips_subject_syntax(tmp_path, monkeypatch):
    """'/O=evil' inside the CN would inject extra RDN fields — the
    subject-syntax chars are stripped, not escaped."""
    _no_cryptography(monkeypatch)
    calls = []
    import types

    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda cmd, **kw: calls.append(cmd) or types.SimpleNamespace(returncode=0, stderr=""),
    )
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    certificates.generate_self_signed(
        str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), common_name="a.com/O=evil"
    )
    subj = calls[0][calls[0].index("-subj") + 1]
    # The /CN= prefix is openssl's own syntax — the injected '/O=evil'
    # must be stripped from the VALUE, leaving exactly one RDN.
    assert subj == "/CN=a.comOevil"


def test_openssl_empty_cn_raises(tmp_path, monkeypatch):
    _no_cryptography(monkeypatch)
    with pytest.raises(ValueError, match="usable characters"):
        certificates.generate_self_signed(
            str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), common_name="/="
        )


def test_openssl_failure_raises_runtime(tmp_path, monkeypatch):
    _no_cryptography(monkeypatch)
    import types

    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda *a, **kw: types.SimpleNamespace(returncode=1, stderr=b"bad usage"),
    )
    with pytest.raises(RuntimeError, match="openssl failed"):
        certificates.generate_self_signed(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))


# ---------------------------------------------------------------------------
# _restrict_key_permissions — Windows ACL branch (mocked)
# ---------------------------------------------------------------------------


def _fake_nt_os(monkeypatch):
    import os as _os
    import types

    fake = types.SimpleNamespace(name="nt", environ=_os.environ)
    monkeypatch.setattr(certificates, "os", fake)
    calls = []
    monkeypatch.setattr(certificates, "run_cmd", lambda cmd, **kw: calls.append(cmd), raising=False)
    return calls


def test_restrict_key_windows_read_grant(monkeypatch):
    calls = _fake_nt_os(monkeypatch)
    monkeypatch.setenv("USERNAME", "alice")
    certificates._restrict_key_permissions(r"C:\k.pem", writable=False)
    assert len(calls) == 2
    assert calls[0][:3] == ["icacls", r"C:\k.pem", "/reset"]
    grant = calls[1]
    assert "/grant:r" in grant
    assert "*S-1-5-18:(R)" in grant and "*S-1-5-32-544:(R)" in grant
    assert "alice:(R)" in grant


def test_restrict_key_windows_modify_grant(monkeypatch):
    calls = _fake_nt_os(monkeypatch)
    monkeypatch.setenv("USERNAME", "alice")
    certificates._restrict_key_permissions(r"C:\state.json", writable=True)
    grant = calls[1]
    assert "*S-1-5-18:(M)" in grant and "alice:(M)" in grant


def test_restrict_key_windows_icacls_failure_suppressed(monkeypatch):
    _fake_nt_os(monkeypatch)

    def _boom(*a, **kw):
        raise OSError("icacls missing")

    monkeypatch.setattr(certificates, "run_cmd", _boom, raising=False)
    certificates._restrict_key_permissions(r"C:\k.pem")  # must not raise


# ---------------------------------------------------------------------------
# create_ssl_context — tls_validation fallback + hardened raise
# ---------------------------------------------------------------------------


def test_ssl_context_fallback_when_tls_validation_missing(tmp_path, monkeypatch):
    """If tls_validation cannot be imported a sane PROTOCOL_TLS_SERVER
    context is built instead of failing."""
    pytest.importorskip("cryptography")
    monkeypatch.setitem(sys.modules, "vnc_remote_secure.security.tls_validation", None)
    monkeypatch.setattr(certificates, "_restrict_key_permissions", lambda *a, **k: None)
    cert = str(tmp_path / "c.pem")
    key = str(tmp_path / "k.pem")
    certificates.generate_self_signed(cert, key)
    monkeypatch.setenv("SSL_CERT", cert)
    monkeypatch.setenv("SSL_KEY", key)
    ctx = certificates.create_ssl_context()
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        assert ctx.options & ssl.OP_NO_COMPRESSION


# ---------------------------------------------------------------------------
# _tls_enabled_env ImportError fallback
# ---------------------------------------------------------------------------


def test_tls_enabled_env_fallback_disable_ssl_wins(monkeypatch):
    """ImportError on the canonical resolver degrades to the local
    DISABLE_SSL/TLS_ENABLED semantics (kill-switch still wins)."""
    monkeypatch.delattr("vnc_remote_secure.core.config._is_tls_enabled_env", raising=False)
    monkeypatch.setenv("DISABLE_SSL", "true")
    monkeypatch.setenv("TLS_ENABLED", "true")
    assert certificates._tls_enabled_env() is False


def test_tls_enabled_env_fallback_tls_enabled_off(monkeypatch):
    monkeypatch.delattr("vnc_remote_secure.core.config._is_tls_enabled_env", raising=False)
    monkeypatch.delenv("DISABLE_SSL", raising=False)
    monkeypatch.setenv("TLS_ENABLED", "false")
    assert certificates._tls_enabled_env() is False
    monkeypatch.setenv("TLS_ENABLED", "true")
    assert certificates._tls_enabled_env() is True


# ---------------------------------------------------------------------------
# _resolve_cert_key_paths — discovery failure degrades
# ---------------------------------------------------------------------------


def test_resolve_cert_key_discovery_failure(monkeypatch):
    monkeypatch.delenv("SSL_CERT", raising=False)
    monkeypatch.delenv("SSL_KEY", raising=False)

    def _boom():
        raise RuntimeError("no paths")

    monkeypatch.setattr("vnc_remote_secure.core.paths.get_ssl_dir", _boom, raising=False)
    assert certificates._resolve_cert_key_paths(None, None) == ("", "")


# ---------------------------------------------------------------------------
# request_letsencrypt — symlink path + failure loop
# ---------------------------------------------------------------------------


def test_letsencrypt_links_certs_into_ssl_dir(tmp_path, monkeypatch):
    import types

    monkeypatch.setattr(certificates.shutil, "which", lambda c: "/usr/bin/certbot")
    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda *a, **kw: types.SimpleNamespace(returncode=0, stderr=""),
    )
    real_exists = os.path.exists
    monkeypatch.setattr(
        "os.path.exists",
        lambda p: p.startswith("/etc/letsencrypt/") or real_exists(p),
    )
    ssl_dir = tmp_path / "linked"
    domain = "ok.example.com"
    assert certificates.request_letsencrypt(domain, "a@b.c", str(ssl_dir)) is True
    link = ssl_dir / "fullchain.pem"
    assert link.is_symlink()
    assert os.readlink(link) == f"/etc/letsencrypt/live/{domain}/fullchain.pem"


def test_letsencrypt_both_plugins_fail(tmp_path, monkeypatch):
    import types

    monkeypatch.setattr(certificates.shutil, "which", lambda c: "/usr/bin/certbot")
    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda *a, **kw: types.SimpleNamespace(returncode=1, stderr="fail"),
    )
    assert certificates.request_letsencrypt("ok.example.com", "a@b.c") is False


def test_letsencrypt_success_but_certs_missing(monkeypatch):
    import types

    monkeypatch.setattr(certificates.shutil, "which", lambda c: "/usr/bin/certbot")
    monkeypatch.setattr(
        certificates,
        "run_cmd",
        lambda *a, **kw: types.SimpleNamespace(returncode=0, stderr=""),
    )
    monkeypatch.setattr("os.path.exists", lambda p: False)
    assert certificates.request_letsencrypt("ok.example.com", "a@b.c") is False
