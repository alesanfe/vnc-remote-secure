"""secret_rotation — generate/persist/check contract.

The rotation path must satisfy three properties: generated values
meet the credential policy (VNC's 8-byte DES cap included), a failed
persist never leaves a half-rotated state, and operator-facing
rotations revoke live sessions via the epoch bump.
"""


import pytest

from vnc_remote_secure.security import secret_rotation as sr


class TestGenerateSecretValue:
    def test_policy_classes_and_length(self):
        for _ in range(30):
            v = sr.generate_secret_value("TTYD_PASSWD")
            assert len(v) == 24
            assert any(c.isupper() for c in v)
            assert any(c.islower() for c in v)
            assert any(c.isdigit() for c in v)
            assert any(c in "!@%^&*" for c in v)

    def test_vnc_capped_at_des_8(self):
        """VNC DES only reads 8 bytes — a longer stored value would
        silently diverge from the effective credential."""
        v = sr.generate_secret_value("VNC_PASSWORD")
        assert len(v) == 8

    def test_values_differ(self):
        assert sr.generate_secret_value("A") != sr.generate_secret_value("A")


class TestRotateSecret:
    def test_non_rotatable_rejected(self):
        with pytest.raises(ValueError, match="cannot rotate"):
            sr.rotate_secret("NOT_A_SECRET")
        with pytest.raises(ValueError):
            sr.rotate_secret("")

    def test_persist_failure_raises_oserror(self, monkeypatch):
        monkeypatch.setattr("vnc_remote_secure.core.config.set_env_persistent", lambda n, v: False)
        with pytest.raises(OSError):
            sr.rotate_secret("TTYD_PASSWD")

    def _stub_write(self, monkeypatch):
        monkeypatch.setattr("vnc_remote_secure.core.config.set_env_persistent", lambda n, v: True)
        monkeypatch.setattr("vnc_remote_secure.core.config._system_env_path", lambda: "")
        monkeypatch.setattr("vnc_remote_secure.core.paths.find_project_root", lambda: "/proj")
        monkeypatch.setattr(sr, "_drop_stale_secret_fallbacks", lambda name: None)

    def test_returns_metadata_never_value(self, monkeypatch):
        self._stub_write(monkeypatch)
        res = sr.rotate_secret("HEALTH_AUTH_TOKEN")
        assert res["name"] == "HEALTH_AUTH_TOKEN"
        assert res["env_path"] == "/proj/.env"
        assert len(res["fingerprint"]) == 8
        assert res["sessions_revoked"] is False
        assert not any(len(str(v)) == 24 for v in res.values())

    @pytest.mark.parametrize("name", ["USER_UI_PASSWORD", "TTYD_PASSWD"])
    def test_operator_credentials_revoke_sessions(self, monkeypatch, name):
        self._stub_write(monkeypatch)
        bumped = []
        monkeypatch.setattr(
            "vnc_remote_secure.security.sessions.bump_operator_epoch",
            lambda: bumped.append(1),
        )
        res = sr.rotate_secret(name)
        assert bumped == [1]
        assert res["sessions_revoked"] is True

    def test_non_operator_credential_no_bump(self, monkeypatch):
        self._stub_write(monkeypatch)
        bumped = []
        monkeypatch.setattr(
            "vnc_remote_secure.security.sessions.bump_operator_epoch",
            lambda: bumped.append(1),
        )
        sr.rotate_secret("BACKUP_PASSWORD")
        assert bumped == []

    def test_bump_failure_still_reports_success(self, monkeypatch):
        """Rotation already persisted — a failed epoch bump must not
        turn the answer into an error."""
        self._stub_write(monkeypatch)
        monkeypatch.setattr(
            "vnc_remote_secure.security.sessions.bump_operator_epoch",
            lambda: (_ for _ in ()).throw(RuntimeError("down")),
        )
        res = sr.rotate_secret("TTYD_PASSWD")
        assert res["sessions_revoked"] is False

    def test_system_env_path_reported_when_key_lives_there(self, monkeypatch, tmp_path):
        sys_env = tmp_path / "config.env"
        sys_env.write_text("TTYD_PASSWD=old\n")
        monkeypatch.setattr("vnc_remote_secure.core.config.set_env_persistent", lambda n, v: True)
        monkeypatch.setattr("vnc_remote_secure.core.config._system_env_path", lambda: str(sys_env))
        monkeypatch.setattr(sr, "_drop_stale_secret_fallbacks", lambda name: None)
        res = sr.rotate_secret("TTYD_PASSWD")
        assert res["env_path"] == str(sys_env)


class TestSecretsCheck:
    def test_aggregates_findings(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.tls_validation.validate_tls_config",
            lambda: [{"severity": "warn", "message": "tls"}],
        )
        monkeypatch.setattr(
            "vnc_remote_secure.security.file_permissions.validate_secret_files",
            lambda: [{"severity": "warn", "message": "perm"}],
        )
        findings = sr.secrets_check()
        assert len(findings) == 2

    def test_validator_failure_is_critical(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.tls_validation.validate_tls_config",
            lambda: (_ for _ in ()).throw(OSError("x")),
        )
        monkeypatch.setattr(
            "vnc_remote_secure.security.file_permissions.validate_secret_files",
            lambda: [],
        )
        findings = sr.secrets_check()
        assert any(f["severity"] == "critical" for f in findings)

    def test_fix_path_remediates_files(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.tls_validation.validate_tls_config",
            lambda: [],
        )
        monkeypatch.setattr(
            "vnc_remote_secure.security.file_permissions.validate_secret_files",
            lambda: [{"severity": "warn", "file": "/x/.env", "message": "perm"}],
        )
        monkeypatch.setattr(
            "vnc_remote_secure.security.file_permissions.fix_secret_file_permissions",
            lambda p: p == "/x/.env",
        )
        rep = sr.secrets_check(fix=True)
        assert rep["fixed"] == [{"file": "/x/.env", "fixed": True}]


class TestRecoveryCodesAndSigning:
    def test_recovery_codes_persisted_as_hashes(self, monkeypatch):
        persisted = {}
        monkeypatch.setattr(
            "vnc_remote_secure.core.config.set_env_persistent",
            lambda n, v: persisted.setdefault(n, v) or True,
        )
        codes = sr.generate_recovery_codes(4)
        assert len(codes) == 4
        stored = persisted["RECOVERY_CODES_HASHES"]
        # Only hashes land in .env — never a plaintext code.
        for c in codes:
            assert c not in stored
        assert len(stored.split(",")) == 4

    def test_recovery_codes_persist_failure(self, monkeypatch):
        monkeypatch.setattr("vnc_remote_secure.core.config.set_env_persistent", lambda n, v: False)
        with pytest.raises(OSError):
            sr.generate_recovery_codes(2)

    def test_signing_rotation_window(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.authentication.rotate_signing_secret",
            lambda: (True, None),
        )
        assert sr.rotate_signing_key() == {"rotated": True, "window_days": 7}

    def test_signing_rotation_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            "vnc_remote_secure.security.authentication.rotate_signing_secret",
            lambda: (False, "key locked"),
        )
        with pytest.raises(RuntimeError, match="key locked"):
            sr.rotate_signing_key()
