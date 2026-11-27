"""Share-link use-case guards: delegation ceiling, label validation,
revocation semantics. Stores are faked at the ``stores`` seam.

Regression focus: the adminish check must evaluate the SAME effective
permissions the session store will persist — an explicit empty
``permissions`` set must not silently fall back to role defaults
after the check has already passed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.engine.application import sessions as uc  # noqa: E402
from vnc_remote_secure.engine.domain.decision import (  # noqa: E402
    ERR_INVALID,
    ERR_PERMISSION,
    UseCaseError,
)


def _fake_stores(monkeypatch, *, role_perms=None):
    """Minimal stores seam: role map + permission expansion + a spy
    session store that records the permissions it was asked to mint."""
    from vnc_remote_secure.engine.infrastructure import stores
    from vnc_remote_secure.security.ephemeral_model import ROLES, expand_permissions

    created = {}

    class _Store:
        def create(self, **kw):
            created.update(kw)
            sess = type("S", (), {"to_dict": lambda s: {"token_id": "t"}})()
            return sess, "signed-token"

        def list_active(self):
            return []

        def list_all(self):
            return []

        def list_revoked(self):
            return []

    monkeypatch.setattr(stores, "session_roles", lambda: ROLES)
    monkeypatch.setattr(
        stores,
        "session_default_permissions",
        lambda role: ROLES.get(role, {"view"}),
    )
    monkeypatch.setattr(stores, "expand_session_permissions", expand_permissions)
    monkeypatch.setattr(stores, "session_store", lambda: _Store())
    monkeypatch.setattr(stores, "session_refresh", lambda s: None)
    monkeypatch.setattr(stores, "audit", lambda *a, **k: None)
    monkeypatch.setattr(stores, "alert_notify", lambda *a, **k: None)
    monkeypatch.setattr(stores, "revoke_ephemeral_token", lambda t: True)
    return created


NONADMIN_PERMS = {"admin_sessions"}  # may create links, no admin:*
ADMIN_PERMS = {"admin:*"}


class TestDelegationCeiling:
    def test_admin_role_requires_admin_star(self, monkeypatch):
        """role=administrator with default perms → adminish → denied."""
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError) as ei:
            uc.create_share_link(
                "op",
                NONADMIN_PERMS,
                role="administrator",
                permissions=None,
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
            )
        assert ei.value.code == ERR_PERMISSION

    def test_explicit_adminish_perm_denied(self, monkeypatch):
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError) as ei:
            uc.create_share_link(
                "op",
                NONADMIN_PERMS,
                role="viewer",
                permissions={"view", "admin_config"},
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
            )
        assert ei.value.code == ERR_PERMISSION

    def test_empty_permissions_with_admin_role_denied(self, monkeypatch):
        """REGRESSION: permissions=[] + role=administrator used to pass
        the check (empty set has no adminish member) while the store
        fell back to ROLES['administrator'] = ALL_PERMISSIONS — a
        non-admin:* operator minting a full-admin link."""
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError) as ei:
            uc.create_share_link(
                "op",
                NONADMIN_PERMS,
                role="administrator",
                permissions=set(),
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
            )
        assert ei.value.code == ERR_PERMISSION

    def test_empty_permissions_with_viewer_role_ok(self, monkeypatch):
        """Same shape but a benign role → role defaults (view) apply."""
        _fake_stores(monkeypatch)
        sess, signed = uc.create_share_link(
            "op",
            NONADMIN_PERMS,
            role="viewer",
            permissions=set(),
            ttl=300,
            single_use=False,
            view_only=False,
            no_terminal=False,
            allowed_ip=None,
            resource=None,
            max_uses=0,
        )
        assert signed == "signed-token"

    def test_admin_star_mints_admin_role(self, monkeypatch):
        _fake_stores(monkeypatch)
        sess, signed = uc.create_share_link(
            "root",
            ADMIN_PERMS,
            role="administrator",
            permissions=None,
            ttl=300,
            single_use=False,
            view_only=False,
            no_terminal=False,
            allowed_ip=None,
            resource=None,
            max_uses=0,
        )
        assert signed == "signed-token"

    def test_non_adminish_custom_perms_allowed(self, monkeypatch):
        """admin_sessions holders may delegate desktop powers — that IS
        the feature; only adminish perms need admin:*."""
        _fake_stores(monkeypatch)
        sess, signed = uc.create_share_link(
            "op",
            NONADMIN_PERMS,
            role="viewer",
            permissions={"view", "terminal_write", "file_transfer"},
            ttl=300,
            single_use=False,
            view_only=False,
            no_terminal=False,
            allowed_ip=None,
            resource=None,
            max_uses=0,
        )
        assert signed == "signed-token"


class TestLabelValidation:
    def test_label_too_long_rejected(self, monkeypatch):
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError) as ei:
            uc.create_share_link(
                "op",
                ADMIN_PERMS,
                role="viewer",
                permissions=None,
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
                label="x" * 65,
            )
        assert ei.value.code == ERR_INVALID

    def test_label_control_chars_rejected(self, monkeypatch):
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError):
            uc.create_share_link(
                "op",
                ADMIN_PERMS,
                role="viewer",
                permissions=None,
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
                label="bad\nlabel",
            )

    def test_label_none_and_empty_ok(self, monkeypatch):
        _fake_stores(monkeypatch)
        for label in (None, "", "   ", "soporte Juan"):
            sess, _ = uc.create_share_link(
                "op",
                ADMIN_PERMS,
                role="viewer",
                permissions=None,
                ttl=300,
                single_use=False,
                view_only=False,
                no_terminal=False,
                allowed_ip=None,
                resource=None,
                max_uses=0,
                label=label,
            )


class TestRevocation:
    def test_revoke_share_link_audits_result(self, monkeypatch):
        audits = []
        _fake_stores(monkeypatch)
        from vnc_remote_secure.engine.infrastructure import stores

        monkeypatch.setattr(
            stores, "audit", lambda ev, actor, detail, result="": audits.append((ev, result))
        )
        uc.revoke_share_link("op", "tid1")
        assert audits and audits[0][1] == "success"

    def test_revoke_all_counts(self, monkeypatch):
        from vnc_remote_secure.engine.infrastructure import stores
        from vnc_remote_secure.security.ephemeral_model import ROLES, expand_permissions

        class _Store:
            def list_active(self):
                return [{"token_id": "a"}, {"token_id": "b"}]

        monkeypatch.setattr(stores, "session_roles", lambda: ROLES)
        monkeypatch.setattr(stores, "expand_session_permissions", expand_permissions)
        monkeypatch.setattr(stores, "session_store", lambda: _Store())
        monkeypatch.setattr(stores, "session_refresh", lambda s: None)
        monkeypatch.setattr(stores, "revoke_ephemeral_token", lambda t: True)
        monkeypatch.setattr(stores, "audit", lambda *a, **k: None)
        monkeypatch.setattr(stores, "alert_notify", lambda *a, **k: None)
        assert uc.revoke_all_share_links("op") == 2

    def test_list_filter_validation(self, monkeypatch):
        _fake_stores(monkeypatch)
        with pytest.raises(UseCaseError):
            uc.list_share_links(status="bogus")
