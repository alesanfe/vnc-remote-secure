"""Never-expiring share links (expires_in=None → expires_at=inf).

The inf sentinel must survive every code path that finite sessions
take — expiry checks, revocation markers, claims, JSON boundaries
(to_dict emits null, from_dict reads it back) — and the custom-role
permission override must hold at the schema boundary.
"""

import math
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))


@pytest.fixture(autouse=True)
def _reset_store():
    import vnc_remote_secure.security.ephemeral_sessions as es

    es._store = None
    yield
    es._store = None


def _store():
    from vnc_remote_secure.security.ephemeral_sessions import get_session_store

    return get_session_store()


class TestNeverExpires:
    def test_create_none_mints_inf(self):
        s, _ = _store().create(role="viewer", expires_in=None)
        assert s.expires_at == math.inf
        assert s.is_valid()

    def test_session_expired_never_true(self):
        from vnc_remote_secure.security.ephemeral_model import _session_expired

        s, _ = _store().create(role="viewer", expires_in=None)
        assert _session_expired(s) is False

    def test_active_lists_keep_it_forever(self):
        store = _store()
        store.create(role="viewer", expires_in=None)
        assert len(store.list_active()) == 1
        # The reaper must not collect it — no finite expiry, no purge.
        assert all(now_ok for now_ok in store.list_active())

    def test_revoke_still_kills(self):
        store = _store()
        s, token = store.create(role="viewer", expires_in=None)
        assert store.validate(token) is not None
        store.revoke(s.token)
        assert store.validate(token) is None

    def test_to_dict_serializes_null_and_roundtrips(self):
        s, _ = _store().create(role="viewer", expires_in=None)
        d = s.to_persist_dict()
        assert d["expires_at"] is None
        from vnc_remote_secure.security.ephemeral_model import EphemeralSession

        back = EphemeralSession.from_dict(d)
        assert back.expires_at == math.inf

    def test_missing_expires_at_stays_expired(self):
        """A legacy record with no expires_at key must NOT resurrect
        as immortal — absent means 'unknown', so it stays expired."""
        s, _ = _store().create(role="viewer", expires_in=60)
        d = s.to_persist_dict()
        del d["expires_at"]
        from vnc_remote_secure.security.ephemeral_model import EphemeralSession

        back = EphemeralSession.from_dict(d)
        assert back.expires_at == 0.0


class TestPreview:
    def test_preview_expires_in_none(self):
        s, signed = _store().create(role="viewer", expires_in=None)
        from vnc_remote_secure.security.ephemeral_sessions import preview_session

        out = preview_session(signed)
        assert out is not None
        assert out["expires_in_seconds"] is None

    def test_preview_finite_still_seconds(self):
        s, signed = _store().create(role="viewer", expires_in=300)
        from vnc_remote_secure.security.ephemeral_sessions import preview_session

        out = preview_session(signed)
        assert 0 < out["expires_in_seconds"] <= 300


class TestSchema:
    def test_ttl_none_accepted(self):
        from vnc_remote_secure.backend.schemas import SessionCreateRequest

        body = SessionCreateRequest(ttl_seconds=None)
        assert body.ttl_seconds is None

    def test_ttl_bounds_still_enforced(self):
        from vnc_remote_secure.backend.schemas import SessionCreateRequest

        with pytest.raises(Exception):
            SessionCreateRequest(ttl_seconds=30)
        with pytest.raises(Exception):
            SessionCreateRequest(ttl_seconds=8 * 86400)

    def test_custom_role_requires_permissions(self):
        from vnc_remote_secure.backend.schemas import SessionCreateRequest

        with pytest.raises(Exception):
            SessionCreateRequest(role="custom")
        body = SessionCreateRequest(role="custom", permissions=["view"])
        assert body.role == "custom"

    def test_custom_permissions_override_role(self):
        from vnc_remote_secure.backend.schemas import SessionCreateRequest

        body = SessionCreateRequest(
            role="viewer", permissions=["view", "terminal_view"]
        )
        assert set(body.permissions) == {"view", "terminal_view"}


class TestCli:
    def test_parse_duration_never(self):
        from vnc_remote_secure.cli.commands.session import _parse_duration

        assert _parse_duration("never") is None
        assert _parse_duration("indefinite") is None
        assert _parse_duration("inf") is None
        assert _parse_duration("30m") == 1800
